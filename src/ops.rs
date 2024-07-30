use core::{
	cell::RefCell,
	future::{Future, IntoFuture},
	marker::PhantomData,
	mem::MaybeUninit,
	num::NonZeroU64,
	pin::Pin,
	task::{Context, Poll},
};

use rustix::io_uring::*;

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

	fn into_sqe(self) -> (&'a RefCell<Uring>, io_uring_sqe);
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
		let (ring, sqe) = uring_op.into_sqe();
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

	fn into_sqe(self) -> (&'a RefCell<Uring>, io_uring_sqe) {
		(self.ring, unsafe { zero!() })
	}

	fn result_from_cqe(_cqe: io_uring_cqe) -> Self::Output {}
}

impl_intofuture!(Nop<'a>);

#[cfg(test)]
mod test {
	use core::cell::RefCell;

	use crate::{block_on, ops::*};

	#[test]
	fn nop() {
		let ring = RefCell::new(Uring::new().unwrap());
		let nop = Nop::new(&ring);

		block_on(&ring, nop.into_future());
	}
}
