use core::{
	cell::RefCell,
	ffi::CStr,
	future::{Future, IntoFuture},
	marker::PhantomData,
	mem::{ManuallyDrop, MaybeUninit},
	num::NonZeroU64,
	pin::Pin,
	task::{Context, Poll},
};

use rustix::{
	fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd},
	fs::{self, Advice},
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
pub unsafe trait UringOp<'a>: Sized {
	type Output;

	fn ring(&self) -> &'a RefCell<Uring>;
	fn into_sqe(self) -> io_uring_sqe;
	fn result_from_cqe(cqe: io_uring_cqe) -> Self::Output;

	fn build(self) -> UringFuture<'a, Self> {
		UringFuture::new(self)
	}
	fn link(self) -> UringFuture<'a, Self> {
		UringFuture::new_link(self)
	}
	fn hardlink(self) -> UringFuture<'a, Self> {
		UringFuture::new_hardlink(self)
	}
	fn drain(self) -> UringFuture<'a, Self> {
		UringFuture::new_drain(self)
	}
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

	fn new_link(uring_op: T) -> Self {
		let ring = uring_op.ring();
		let mut sqe = uring_op.into_sqe();
		sqe.flags |= IoringSqeFlags::IO_LINK;
		Self(unsafe { InternalOp::new(ring, sqe) }, PhantomData)
	}

	fn new_hardlink(uring_op: T) -> Self {
		let ring = uring_op.ring();
		let mut sqe = uring_op.into_sqe();
		sqe.flags |= IoringSqeFlags::IO_HARDLINK;
		Self(unsafe { InternalOp::new(ring, sqe) }, PhantomData)
	}

	fn new_drain(uring_op: T) -> Self {
		let ring = uring_op.ring();
		let mut sqe = uring_op.into_sqe();
		sqe.flags |= IoringSqeFlags::IO_DRAIN;
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

impl Future for InternalOp<'_> {
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
			Some(cqe) => {
				this.ticket = None;
				Poll::Ready(cqe.0)
			}
		}
	}
}

impl Drop for InternalOp<'_> {
	fn drop(&mut self) {
		let ticket = match self.ticket {
			Some(t) => t,
			None => return,
		};

		let mut sqe: io_uring_sqe = unsafe { zero!() };
		sqe.opcode = IoringOp::AsyncCancel;
		sqe.fd = -1;
		sqe.addr_or_splice_off_in = addr_or_splice_off_in_union {
			addr: io_uring_ptr::from(ticket.get() as *mut _),
		};
		sqe.op_flags = op_flags_union {
			cancel_flags: IoringAsyncCancelFlags::empty(),
		};

		fn inner_block_on<F: Future>(ring: &RefCell<Uring>, fut: &mut F) {
			let mut cx = Context::from_waker(Waker::noop());
			loop {
				let f = unsafe { Pin::new_unchecked(&mut *fut) };

				if Future::poll(f, &mut cx).is_ready() {
					break;
				} else {
					ring.borrow_mut().submit(1);
				}
			}
		}

		let mut cancel = ManuallyDrop::new(unsafe { InternalOp::new(self.ring, sqe) });

		inner_block_on(self.ring, cancel.deref_mut());
		// Wait for original op to finish, whether by fully completing or being canceled.
		inner_block_on(self.ring, self);
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
pub struct Close<'a> {
	ring: &'a RefCell<Uring>,
	fd: OwnedFd,
}

impl<'a> Close<'a> {
	pub fn new(ring: &'a RefCell<Uring>, fd: OwnedFd) -> Self {
		Self { ring, fd }
	}
}

unsafe impl<'a> UringOp<'a> for Close<'a> {
	type Output = ();

	fn ring(&self) -> &'a RefCell<Uring> {
		self.ring
	}

	fn into_sqe(self) -> io_uring_sqe {
		let mut sqe: io_uring_sqe = unsafe { zero!() };
		sqe.opcode = IoringOp::Close;
		sqe.fd = self.fd.into_raw_fd();
		sqe
	}

	fn result_from_cqe(_cqe: io_uring_cqe) -> Self::Output {}
}

impl_intofuture!(Close<'a>);

#[derive(Debug)]
pub struct Fadvise<'a> {
	ring: &'a RefCell<Uring>,
	fd: BorrowedFd<'a>,
	offset: u64,
	len: u32,
	advice: Advice,
}

impl<'a> Fadvise<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		fd: BorrowedFd<'a>,
		offset: u64,
		len: u32,
		advice: Advice,
	) -> Self {
		Self {
			ring,
			fd,
			offset,
			len,
			advice,
		}
	}
}

unsafe impl<'a> UringOp<'a> for Fadvise<'a> {
	type Output = PosixResult<()>;

	fn ring(&self) -> &'a RefCell<Uring> {
		self.ring
	}

	fn into_sqe(self) -> io_uring_sqe {
		let mut sqe: io_uring_sqe = unsafe { zero!() };
		sqe.opcode = IoringOp::Fadvise;
		sqe.fd = self.fd.as_raw_fd();
		sqe.off_or_addr2 = off_or_addr2_union { off: self.offset };
		sqe.len = len_union { len: self.len };
		sqe.op_flags = op_flags_union {
			fadvise_advice: self.advice,
		};
		sqe
	}

	fn result_from_cqe(cqe: io_uring_cqe) -> Self::Output {
		posix_result(cqe.res).map(|_| ())
	}
}

impl_intofuture!(Fadvise<'a>);

#[derive(Debug)]
pub struct Openat2<'a> {
	ring: &'a RefCell<Uring>,
	dfd: BorrowedFd<'a>,
	path: &'a CStr,
	open_how: &'a open_how,
}

impl<'a> Openat2<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		dfd: BorrowedFd<'a>,
		path: &'a CStr,
		open_how: &'a open_how,
	) -> Self {
		Self {
			ring,
			dfd,
			path,
			open_how,
		}
	}
}

unsafe impl<'a> UringOp<'a> for Openat2<'a> {
	type Output = PosixResult<OwnedFd>;

	fn ring(&self) -> &'a RefCell<Uring> {
		self.ring
	}

	fn into_sqe(self) -> io_uring_sqe {
		let mut sqe: io_uring_sqe = unsafe { zero!() };
		sqe.opcode = IoringOp::Openat2;
		sqe.fd = self.dfd.as_raw_fd();
		sqe.addr_or_splice_off_in = addr_or_splice_off_in_union {
			addr: io_uring_ptr::from(self.path.as_ptr().cast_mut().cast()),
		};
		sqe.off_or_addr2 = off_or_addr2_union {
			addr2: io_uring_ptr::from(self.open_how as *const _ as *mut _),
		};
		sqe.len = len_union {
			len: size_of::<open_how>().try_into().unwrap(),
		};
		sqe
	}

	fn result_from_cqe(cqe: io_uring_cqe) -> Self::Output {
		posix_result(cqe.res).map(|x| unsafe { OwnedFd::from_raw_fd(x as i32) })
	}
}

impl_intofuture!(Openat2<'a>);

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

#[derive(Debug)]
pub struct Statx<'a> {
	ring: &'a RefCell<Uring>,
	dfd: BorrowedFd<'a>,
	path: &'a CStr,
	flags: AtFlags,
	mask: StatxFlags,
	buf: &'a mut fs::Statx,
}

impl<'a> Statx<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		dfd: BorrowedFd<'a>,
		path: &'a CStr,
		flags: AtFlags,
		mask: StatxFlags,
		buf: &'a mut fs::Statx,
	) -> Self {
		Self {
			ring,
			dfd,
			path,
			flags,
			mask,
			buf,
		}
	}
}

unsafe impl<'a> UringOp<'a> for Statx<'a> {
	type Output = PosixResult<()>;

	fn ring(&self) -> &'a RefCell<Uring> {
		self.ring
	}

	fn into_sqe(self) -> io_uring_sqe {
		let mut sqe: io_uring_sqe = unsafe { zero!() };
		sqe.opcode = IoringOp::Statx;
		sqe.fd = self.dfd.as_raw_fd();
		sqe.addr_or_splice_off_in = addr_or_splice_off_in_union {
			addr: io_uring_ptr::from(self.path.as_ptr().cast_mut().cast()),
		};
		sqe.off_or_addr2 = off_or_addr2_union {
			addr2: io_uring_ptr::from(self.buf as *mut _ as *mut _),
		};
		sqe.len = len_union {
			len: self.mask.bits(),
		};
		sqe.op_flags = op_flags_union {
			statx_flags: self.flags,
		};
		sqe
	}

	fn result_from_cqe(cqe: io_uring_cqe) -> Self::Output {
		posix_result(cqe.res).map(|_| {})
	}
}

impl_intofuture!(Statx<'a>);

#[cfg(test)]
mod test {
	use core::{cell::RefCell, hint::black_box};

	use ops::Statx;
	use rustix::{
		fd::AsFd,
		fs::{self, open, CWD},
		io,
		pipe::pipe,
	};

	use crate::{block_on, ops::*};

	#[test]
	fn op_drop() {
		let ring = RefCell::new(Uring::new().unwrap());

		let file = fs::open("/dev/zero", OFlags::RDONLY, Mode::empty()).unwrap();
		let mut buf = [1];

		let read = Read::new(&ring, file.as_fd(), 0, &mut buf).build();
		// Note: `read` is not submitted yet because the queue hasn't filled up and nothing's awaiting.

		drop(read);
		let buf_before = buf;

		{
			// Submit everything in the sq.
			let mut borrowed = ring.borrow_mut();
			let enqueued = borrowed.sq_enqueued().into();
			borrowed.submit(enqueued);
		}

		// idk if the compiler will try to merge this next assert with the previous.
		black_box(&mut buf);

		assert_eq!(buf, buf_before);
		// Also make sure it doesn't leak.
		assert_eq!(ring.borrow_mut().map_entries(), 0);
	}

	#[test]
	fn link() {
		let ring = RefCell::new(Uring::new().unwrap());

		let (rx, tx) = pipe().unwrap();
		let tx = tx.as_fd();
		let rx = rx.as_fd();

		let mut b1 = [0];
		let r1 = Read::new(&ring, rx, u64::MAX, &mut b1).link();
		let mut b2 = [0];
		let r2 = Read::new(&ring, rx, u64::MAX, &mut b2).hardlink();
		let mut b3 = [0];
		let r3 = Read::new(&ring, rx, u64::MAX, &mut b3).drain();
		let mut b4 = [0];
		let r4 = Read::new(&ring, rx, u64::MAX, &mut b4).build();

		ring.borrow_mut().submit(0);

		for i in 1..=5 {
			io::write(tx, &[i]).unwrap();
		}

		block_on(&ring, async {
			r1.await.unwrap();
			r2.await.unwrap();
			r3.await.unwrap();
			r4.await.unwrap();
		});

		assert_eq!(b1, [1]);
		assert_eq!(b2, [2]);
		assert_eq!(b3, [3]);
		assert_eq!(b4, [4]);
	}

	#[test]
	fn nop() {
		let ring = RefCell::new(Uring::new().unwrap());
		let nop = Nop::new(&ring);

		block_on(&ring, nop.into_future());
	}

	#[test]
	fn close() {
		let ring = RefCell::new(Uring::new().unwrap());

		// It's important that the path be to a unique inode because this races with other tests opening files.
		let fd = fs::open("/dev/mem", OFlags::PATH, Mode::empty()).unwrap();
		let ino = fs::statat(fd.as_fd(), "", AtFlags::EMPTY_PATH)
			.unwrap()
			.st_ino;

		block_on(&ring, Close::new(&ring, fd).into_future());

		let new_fd = open("/dev/mem", OFlags::PATH, Mode::empty()).unwrap();

		match fs::statat(new_fd.as_fd(), "", AtFlags::EMPTY_PATH) {
			Ok(x) if x.st_ino == ino => (),
			Err(Errno::BADF) => (),
			x => panic!("{:?}", x),
		}
	}

	#[test]
	fn fadvise() {
		let ring = RefCell::new(Uring::new().unwrap());
		let fd = fs::open("/dev/zero", OFlags::RDONLY, Mode::empty()).unwrap();

		let ret = block_on(
			&ring,
			Fadvise::new(&ring, fd.as_fd(), 0, 0, Advice::Random).into_future(),
		);
		assert!(ret.is_ok());
	}

	#[test]
	fn openat2() {
		let ring = RefCell::new(Uring::new().unwrap());

		let how = open_how {
			flags: OFlags::RDONLY.bits().into(),
			mode: 0,
			resolve: ResolveFlags::empty(),
		};
		let fd = block_on(
			&ring,
			Openat2::new(&ring, CWD, c"/dev/null", &how).into_future(),
		)
		.unwrap();

		assert_eq!(io::read(fd, &mut [0]), Ok(0));
	}

	#[test]
	fn read() {
		let ring = RefCell::new(Uring::new().unwrap());

		let file = fs::open("/dev/zero", OFlags::RDONLY, Mode::empty()).unwrap();
		let mut buf = [1u8; 64];

		let res = block_on(
			&ring,
			Read::new(&ring, file.as_fd(), 0, &mut buf).into_future(),
		)
		.unwrap();
		assert_eq!(res as usize, buf.len());
		assert_eq!(buf, [0u8; 64]);
	}

	#[test]
	fn statx() {
		let ring = RefCell::new(Uring::new().unwrap());

		let mut buf = unsafe { zero!() };
		block_on(
			&ring,
			Statx::new(
				&ring,
				CWD,
				c"/dev/null",
				AtFlags::empty(),
				StatxFlags::BASIC_STATS,
				&mut buf,
			)
			.into_future(),
		)
		.unwrap();

		assert_eq!(buf.stx_rdev_major, 1);
		assert_eq!(buf.stx_rdev_minor, 3);
	}
}
