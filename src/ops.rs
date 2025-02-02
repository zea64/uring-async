use core::{
	cell::RefCell,
	ffi::CStr,
	future::Future,
	marker::PhantomPinned,
	mem,
	pin::Pin,
	task::{Context, Poll, Waker},
};

use rustix::{
	fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd},
	fs,
	fs::StatxFlags,
	io::Result as PosixResult,
};

use crate::*;

#[derive(Debug, Default)]
pub struct Op(PendingCqe);

impl Op {
	pub fn new() -> Self {
		Self::default()
	}

	/// # Safety
	/// `Sqe` will be passed almost directly to io_uring, and the low-level unsafe power it weilds.
	pub unsafe fn activate(self: Pin<&mut Self>, ring: &mut Uring, mut sqe: Sqe) {
		let this = &mut unsafe { Pin::into_inner_unchecked(self) }.0;
		*this = PendingCqe::Pending(Waker::noop().clone(), PhantomPinned);

		sqe.user_data.ptr = io_uring_ptr {
			ptr: (&raw mut *this).cast(),
		};
		ring.push(sqe);
	}
}

impl Future for Op {
	type Output = Cqe;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = &mut unsafe { Pin::into_inner_unchecked(self) }.0;
		match this {
			PendingCqe::Pending(waker, _) => {
				waker.clone_from(cx.waker());
				Poll::Pending
			}
			PendingCqe::Complete(cqe) => Poll::Ready(cqe.clone()),
		}
	}
}

#[derive(Debug)]
enum OpWrapper<'a, T: Debug> {
	Before((&'a RefCell<Uring>, T)),
	After(Op),
}

impl<'a, T: Debug> OpWrapper<'a, T> {
	fn new(ring: &'a RefCell<Uring>, before: T) -> Self {
		Self::Before((ring, before))
	}

	fn poll(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		sqe_factory: impl FnOnce(T) -> Sqe,
	) -> Poll<Cqe> {
		let this = unsafe { Pin::into_inner_unchecked(self) };
		match this {
			Self::Before(_) => {
				// This lets us take ownership of the current `this`, while also replacing it with the new version it'll need.
				let (ring, before) = match mem::replace(this, OpWrapper::After(Op::default())) {
					Self::Before((ring, before)) => (ring, before),
					_ => unreachable!(),
				};

				let sqe = sqe_factory(before);

				match this {
					Self::After(op) => {
						unsafe {
							Pin::new_unchecked(op).activate(ring.borrow_mut().deref_mut(), sqe)
						};
					}
					_ => unreachable!(),
				}

				Poll::Pending
			}
			Self::After(op) => unsafe { Pin::new_unchecked(op) }.poll(cx),
		}
	}
}

#[derive(Debug)]
pub struct Nop<'a>(OpWrapper<'a, ()>);

impl<'a> Nop<'a> {
	pub fn new(ring: &'a RefCell<Uring>) -> Self {
		Self(OpWrapper::new(ring, ()))
	}
}

impl Future for Nop<'_> {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let inner = unsafe { Pin::new_unchecked(&mut Pin::into_inner_unchecked(self).0) };
		inner
			.poll(cx, |_| {
				Sqe(io_uring_sqe {
					opcode: IoringOp::Nop,
					..Default::default()
				})
			})
			.map(|_| ())
	}
}

#[derive(Debug)]
pub struct Close<'a>(OpWrapper<'a, OwnedFd>);

impl<'a> Close<'a> {
	pub fn new(ring: &'a RefCell<Uring>, fd: OwnedFd) -> Self {
		Self(OpWrapper::new(ring, fd))
	}
}

impl Future for Close<'_> {
	type Output = PosixResult<()>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let inner = unsafe { Pin::new_unchecked(&mut Pin::into_inner_unchecked(self).0) };
		inner
			.poll(cx, |fd| {
				Sqe(io_uring_sqe {
					opcode: IoringOp::Close,
					fd: fd.into_raw_fd(),
					..Default::default()
				})
			})
			.map(|cqe| posix_result(cqe.res).map(|_| ()))
	}
}

#[derive(Debug)]
pub struct Fadvise<'a>(OpWrapper<'a, (BorrowedFd<'a>, u64, u32, fs::Advice)>);

impl<'a> Fadvise<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		fd: BorrowedFd<'a>,
		offset: u64,
		len: u32,
		advice: fs::Advice,
	) -> Self {
		Self(OpWrapper::new(ring, (fd, offset, len, advice)))
	}
}

impl Future for Fadvise<'_> {
	type Output = PosixResult<()>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let inner = unsafe { Pin::new_unchecked(&mut Pin::into_inner_unchecked(self).0) };
		inner
			.poll(cx, |(fd, offset, len, advice)| {
				Sqe(io_uring_sqe {
					opcode: IoringOp::Fadvise,
					fd: fd.as_raw_fd(),
					off_or_addr2: off_or_addr2_union { off: offset },
					len: len_union { len },
					op_flags: op_flags_union {
						fadvise_advice: advice,
					},
					..Default::default()
				})
			})
			.map(|cqe| posix_result(cqe.res).map(|_| ()))
	}
}

#[derive(Debug)]
pub struct Openat2<'a>(OpWrapper<'a, (BorrowedFd<'a>, &'a CStr, &'a open_how)>);

impl<'a> Openat2<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		fd: BorrowedFd<'a>,
		path: &'a CStr,
		how: &'a open_how,
	) -> Self {
		Self(OpWrapper::new(ring, (fd, path, how)))
	}
}

impl Future for Openat2<'_> {
	type Output = PosixResult<OwnedFd>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let inner = unsafe { Pin::new_unchecked(&mut Pin::into_inner_unchecked(self).0) };
		inner
			.poll(cx, |(fd, path, how)| {
				Sqe(io_uring_sqe {
					opcode: IoringOp::Openat2,
					fd: fd.as_raw_fd(),
					addr_or_splice_off_in: addr_or_splice_off_in_union {
						addr: io_uring_ptr::from(path.as_ptr().cast_mut().cast()),
					},
					off_or_addr2: off_or_addr2_union {
						addr2: io_uring_ptr::from((&raw const *how).cast_mut().cast()),
					},
					len: len_union {
						len: size_of::<open_how>().try_into().unwrap(),
					},
					..Default::default()
				})
			})
			.map(|cqe| {
				posix_result(cqe.res).map(|raw_fd| unsafe { OwnedFd::from_raw_fd(raw_fd as i32) })
			})
	}
}

#[derive(Debug)]
pub struct Read<'a>(OpWrapper<'a, (BorrowedFd<'a>, u64, &'a mut [u8])>);

impl<'a> Read<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		fd: BorrowedFd<'a>,
		offset: u64,
		buf: &'a mut [u8],
	) -> Self {
		Self(OpWrapper::new(ring, (fd, offset, buf)))
	}
}

impl Future for Read<'_> {
	type Output = PosixResult<u32>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let inner = unsafe { Pin::new_unchecked(&mut Pin::into_inner_unchecked(self).0) };
		inner
			.poll(cx, |(fd, offset, buf)| {
				Sqe(io_uring_sqe {
					opcode: IoringOp::Read,
					fd: fd.as_raw_fd(),
					off_or_addr2: off_or_addr2_union { off: offset },
					addr_or_splice_off_in: addr_or_splice_off_in_union {
						addr: io_uring_ptr::from(buf.as_mut_ptr().cast()),
					},
					len: len_union {
						len: buf.len().try_into().unwrap(),
					},
					..Default::default()
				})
			})
			.map(|cqe| posix_result(cqe.res))
	}
}

#[derive(Debug)]
pub struct Statx<'a>(
	OpWrapper<
		'a,
		(
			BorrowedFd<'a>,
			&'a CStr,
			AtFlags,
			StatxFlags,
			&'a mut fs::Statx,
		),
	>,
);

impl<'a> Statx<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		dfd: BorrowedFd<'a>,
		path: &'a CStr,
		flags: AtFlags,
		mask: StatxFlags,
		buf: &'a mut fs::Statx,
	) -> Self {
		Self(OpWrapper::new(ring, (dfd, path, flags, mask, buf)))
	}
}

impl Future for Statx<'_> {
	type Output = PosixResult<()>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let inner = unsafe { Pin::new_unchecked(&mut Pin::into_inner_unchecked(self).0) };
		inner
			.poll(cx, |(fd, path, flags, mask, buf)| {
				Sqe(io_uring_sqe {
					opcode: IoringOp::Statx,
					fd: fd.as_raw_fd(),
					addr_or_splice_off_in: addr_or_splice_off_in_union {
						addr: io_uring_ptr::from(path.as_ptr().cast_mut().cast()),
					},
					op_flags: op_flags_union { statx_flags: flags },
					len: len_union { len: mask.bits() },
					off_or_addr2: off_or_addr2_union {
						addr2: io_uring_ptr::from((&raw mut *buf).cast()),
					},
					..Default::default()
				})
			})
			.map(|cqe| posix_result(cqe.res).map(|_| ()))
	}
}

#[cfg(test)]
mod test {
	use core::{cell::RefCell, mem::MaybeUninit};

	use rustix::{
		fd::{AsFd, AsRawFd, BorrowedFd},
		fs::{self, AtFlags, Mode, OFlags, CWD},
		io,
	};

	use crate::*;

	#[test]
	fn nop() {
		let ring = RefCell::new(Uring::new().unwrap());

		let nop = ops::Nop::new(&ring);
		block_on(&ring, nop);
	}

	#[test]
	fn close() {
		let ring = RefCell::new(Uring::new().unwrap());

		let file = fs::open("/", OFlags::RDONLY, Mode::empty()).unwrap();
		let hanging_fd = unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) };

		let ino = fs::statat(file.as_fd(), "", AtFlags::EMPTY_PATH)
			.unwrap()
			.st_ino;

		block_on(&ring, ops::Close::new(&ring, file)).unwrap();

		// Check the fd again.
		match fs::statat(hanging_fd, "", AtFlags::EMPTY_PATH) {
			// Good, it should be closed.
			Err(_) => (),
			// Is it the same inode?
			Ok(s) => assert_ne!(ino, s.st_ino),
		}
	}

	#[test]
	fn fadvise() {
		let ring = RefCell::new(Uring::new().unwrap());
		let fd = fs::open("/dev/zero", OFlags::RDONLY, Mode::empty()).unwrap();

		let res = block_on(
			&ring,
			ops::Fadvise::new(&ring, fd.as_fd(), 0, 0, Advice::Random),
		);
		assert!(res.is_ok());
	}

	#[test]
	fn openat2() {
		let ring = RefCell::new(Uring::new().unwrap());

		let how = open_how {
			flags: OFlags::RDONLY.bits().into(),
			mode: 0,
			resolve: ResolveFlags::empty(),
		};
		let fd = block_on(&ring, ops::Openat2::new(&ring, CWD, c"/dev/null", &how)).unwrap();

		assert_eq!(io::read(fd, &mut [0]), Ok(0));
	}

	#[test]
	fn read() {
		let ring = RefCell::new(Uring::new().unwrap());

		let file = fs::open("/dev/zero", OFlags::RDONLY, Mode::empty()).unwrap();
		let mut buf = [1u8; 64];

		let res = block_on(&ring, ops::Read::new(&ring, file.as_fd(), 0, &mut buf));

		assert_eq!(res, Ok(buf.len() as u32));
		assert_eq!(buf, [0u8; 64]);
	}

	#[test]
	fn statx() {
		let ring = RefCell::new(Uring::new().unwrap());

		let mut buf = unsafe { MaybeUninit::zeroed().assume_init() };
		block_on(
			&ring,
			ops::Statx::new(
				&ring,
				CWD,
				c"/dev/null",
				AtFlags::empty(),
				StatxFlags::BASIC_STATS,
				&mut buf,
			),
		)
		.unwrap();

		assert_eq!(buf.stx_rdev_major, 1);
		assert_eq!(buf.stx_rdev_minor, 3);
	}
}
