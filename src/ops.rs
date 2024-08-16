use core::{
	cell::RefCell,
	future::{Future, IntoFuture},
	marker::PhantomData,
	mem::MaybeUninit,
	num::NonZeroU64,
	pin::Pin,
	task::{Context, Poll},
};

use rustix::{
	fd::{AsRawFd, BorrowedFd},
	io_uring::*,
};

use crate::*;

macro_rules! zero {
	() => {
		MaybeUninit::zeroed().assume_init()
	};
}

/// # Safety
/// This relies raw `io_uring_sqe` and provides a raw `io_uring_cqe`.
/// Implementors of this trait must ensure their `into_sqe` doesn't violate memory safety when passed to io_uring and that they can safely create an output in `result_from_cqe`.
pub unsafe trait UringOp<'a> {
	type Output;

	fn ring(&self) -> &'a RefCell<Uring>;
	fn into_sqe(self) -> io_uring_sqe;
	fn result_from_cqe(cqe: io_uring_cqe) -> Self::Output;
}

macro_rules! impl_intofuture {
	($t:ty) => {
		impl<'a> IntoFuture for $t {
			type IntoFuture = UringFuture<'a, $t>;
			type Output = <$t as UringOp<'a>>::Output;

			fn into_future(self) -> Self::IntoFuture {
				UringFuture::new(self)
			}
		}
	};
}

pub struct UringFuture<'a, T: UringOp<'a>>(InternalOp<'a>, PhantomData<T>);

impl<'a, T: UringOp<'a>> UringFuture<'a, T> {
	fn new(uring_op: T) -> Self {
		let ring = uring_op.ring();
		let sqe = uring_op.into_sqe();
		Self(unsafe { InternalOp::new(ring, sqe) }, PhantomData)
	}
}

impl<'a, T: UringOp<'a>> Future for UringFuture<'a, T> {
	type Output = T::Output;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let op = unsafe { self.map_unchecked_mut(|x| &mut x.0) };
		op.poll(cx).map(|cqe| T::result_from_cqe(cqe))
	}
}

#[derive(Debug)]
struct InternalOp<'a> {
	ring: &'a RefCell<Uring>,
	ticket: Option<NonZeroU64>,
}

impl<'a> InternalOp<'a> {
	unsafe fn new(ring: &'a RefCell<Uring>, mut sqe: io_uring_sqe) -> Self {
		let mut borrowed_ring = ring.borrow_mut();
		let ticket = borrowed_ring.get_ticket();
		sqe.user_data.u64_ = ticket.into();
		borrowed_ring.push(unsafe { Sqe::new(sqe) }).unwrap();
		Self {
			ring,
			ticket: Some(ticket),
		}
	}
}

impl<'a> Future for InternalOp<'a> {
	type Output = io_uring_cqe;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = Pin::into_inner(self);

		// Fuse future
		let ticket = match this.ticket {
			Some(t) => t,
			None => return Poll::Pending,
		};

		match this.ring.borrow_mut().poll(ticket.into(), Some(cx)) {
			None => Poll::Pending,
			Some(cqe) => Poll::Ready(cqe.0),
		}
	}
}

#[derive(Debug)]
pub struct Nop<'a> {
	ring: &'a RefCell<Uring>,
}

impl<'a> Nop<'a> {
	pub fn new(ring: &'a RefCell<Uring>) -> Self {
		Self { ring }
	}
}

unsafe impl<'a> UringOp<'a> for Nop<'a> {
	type Output = ();

	fn ring(&self) -> &'a RefCell<Uring> {
		self.ring
	}

	fn into_sqe(self) -> io_uring_sqe {
		unsafe { zero!() }
	}

	fn result_from_cqe(_cqe: io_uring_cqe) -> Self::Output {}
}

impl_intofuture!(Nop<'a>);

#[derive(Debug)]
pub struct Read<'a> {
	ring: &'a RefCell<Uring>,
	fd: BorrowedFd<'a>,
	offset: u64,
	buf: &'a mut [u8],
}

impl<'a> Read<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		fd: BorrowedFd<'a>,
		offset: u64,
		buf: &'a mut [u8],
	) -> Self {
		Self {
			ring,
			fd,
			buf,
			offset,
		}
	}
}

unsafe impl<'a> UringOp<'a> for Read<'a> {
	type Output = PosixResult<u32>;

	fn ring(&self) -> &'a RefCell<Uring> {
		self.ring
	}

	fn into_sqe(self) -> io_uring_sqe {
		let mut sqe: io_uring_sqe = unsafe { zero!() };
		sqe.opcode = IoringOp::Read;
		sqe.fd = self.fd.as_raw_fd();
		sqe.off_or_addr2 = off_or_addr2_union { off: self.offset };
		sqe.addr_or_splice_off_in = addr_or_splice_off_in_union {
			addr: io_uring_ptr {
				ptr: self.buf.as_mut_ptr().cast(),
			},
		};
		sqe.len = len_union {
			len: self.buf.len().try_into().unwrap(),
		};
		sqe
	}

	fn result_from_cqe(cqe: io_uring_cqe) -> Self::Output {
		posix_result(cqe.res)
	}
}

impl_intofuture!(Read<'a>);

#[cfg(test)]
mod test {
	use core::cell::RefCell;

	use rustix::{fd::AsFd, fs::open};

	use crate::{block_on, ops::*};

	#[test]
	fn nop() {
		let ring = RefCell::new(Uring::new().unwrap());
		let nop = Nop::new(&ring);

		block_on(&ring, nop.into_future());
	}

	#[test]
	fn read() {
		let ring = RefCell::new(Uring::new().unwrap());

		let file = open("/dev/zero", OFlags::RDONLY, Mode::empty()).unwrap();
		let mut buf = [1u8; 64];

		let res = block_on(
			&ring,
			Read::new(&ring, file.as_fd(), 0, &mut buf).into_future(),
		)
		.unwrap();
		assert_eq!(res as usize, buf.len());
		assert_eq!(buf, [0u8; 64]);
	}
}
