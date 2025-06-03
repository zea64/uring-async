use core::{
	cell::RefCell,
	ffi::CStr,
	marker::PhantomPinned,
	mem::{self, MaybeUninit},
	pin::Pin,
	ptr::NonNull,
	task::{Context, Poll, Waker},
};

use rustix::{
	fd::{FromRawFd, IntoRawFd, OwnedFd},
	fs::{AtFlags, Mode, OFlags, StatxFlags},
	io_uring::*,
};

use crate::{fd::*, *};

const ZERO_SQE: io_uring_sqe = unsafe { MaybeUninit::zeroed().assume_init() };

fn error_code(res: i32) -> Result<i32, Errno> {
	if res < 0 {
		Err(Errno::from_raw_os_error(-res))
	} else {
		Ok(res)
	}
}

#[derive(Debug)]
enum OpInner {
	Pending(Waker),
	Ready { res: i32, flags: IoringCqeFlags },
}

impl Default for OpInner {
	fn default() -> Self {
		Self::Pending(Waker::noop().clone())
	}
}

#[derive(Debug)]
#[must_use]
#[repr(C)]
pub struct Op {
	callback: CompletionCallback,
	inner: OpInner,
	_marker: PhantomPinned,
}

impl Op {
	unsafe fn op_completion_callback(this: *mut (), cqe: io_uring_cqe) -> bool {
		let this: &mut Op = unsafe { &mut *this.cast() };
		match mem::replace(
			&mut this.inner,
			OpInner::Ready {
				res: cqe.res,
				flags: cqe.flags,
			},
		) {
			OpInner::Pending(waker) => waker.wake(),
			OpInner::Ready { .. } => unreachable!(),
		};
		true
	}

	pub fn new() -> Self {
		Self {
			callback: Some(Self::op_completion_callback),
			inner: OpInner::Pending(Waker::noop().clone()),
			_marker: PhantomPinned,
		}
	}

	pub fn init(self: Pin<&mut Self>, ring: &mut Uring, sqe: io_uring_sqe) {
		unsafe {
			let this = Pin::into_inner_unchecked(self);
			ring.push(Sqe::new(
				sqe,
				NonNull::new_unchecked(&raw mut this.callback),
			))
			.unwrap();
		}
	}
}

impl Default for Op {
	fn default() -> Self {
		Self::new()
	}
}

impl Future for Op {
	type Output = (i32, IoringCqeFlags);

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = unsafe { Pin::into_inner_unchecked(self) };

		match this.inner {
			OpInner::Pending(..) => {
				this.inner = OpInner::Pending(cx.waker().clone());
				Poll::Pending
			}
			OpInner::Ready { res, flags } => {
				this.inner = OpInner::Pending(Waker::noop().clone());
				Poll::Ready((res, flags))
			}
		}
	}
}

pub async fn nop(ring: &RefCell<Uring>) {
	let mut sqe = ZERO_SQE;
	sqe.opcode = IoringOp::Nop;

	let mut op = Op::new();
	Op::init(
		unsafe { Pin::new_unchecked(&mut op) },
		&mut ring.borrow_mut(),
		sqe,
	);

	unsafe { Pin::new_unchecked(&mut op) }.await;
}

#[derive(Debug)]
#[repr(C)]
struct CompletionNotifier {
	callback: CompletionCallback,
	orig_callback: *mut CompletionCallback,
	waker: Option<Waker>,
}

impl CompletionNotifier {
	unsafe fn callback(this: *mut (), cqe: io_uring_cqe) -> bool {
		let this: &mut CompletionNotifier = unsafe { &mut *this.cast() };
		this.waker.take().unwrap().wake();

		if let Some(f) = &unsafe { *this.orig_callback } {
			unsafe { f(this.orig_callback.cast(), cqe) }
		} else {
			true
		}
	}

	fn new(orig_callback: *mut CompletionCallback) -> Self {
		Self {
			callback: Some(Self::callback),
			orig_callback,
			waker: Some(Waker::noop().clone()),
		}
	}
}

impl Future for CompletionNotifier {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = unsafe { Pin::into_inner_unchecked(self) };

		match this.waker {
			None => Poll::Ready(()),
			Some(ref mut waker) => {
				*waker = cx.waker().clone();
				Poll::Pending
			}
		}
	}
}

pub async fn link<'a, F: Future>(
	ring: &'a RefCell<Uring>,
	mut fut: Pin<&'a mut F>,
) -> Pin<&'a mut F> {
	// Make sure it ends up in the ring.
	// For our io_uring futures, we can guarantee it will not complete on first poll.
	match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
		Poll::Pending => (),
		Poll::Ready(_) => unimplemented!(),
	}

	let mut borrowed_ring = ring.borrow_mut();
	let mut sq = borrowed_ring.sq();

	let len = sq.len();
	let capacity = sq.capacity();

	let sqe = match sq.get_last() {
		Some(s) => s,
		None => return fut,
	};

	sqe.flags |= IoringSqeFlags::IO_LINK;

	if len != capacity {
		return fut;
	}

	let orig_obj: &mut CompletionCallback = unsafe { &mut *sqe.user_data.ptr.ptr.cast() };
	let mut notifier = CompletionNotifier::new(orig_obj);

	sqe.user_data = io_uring_user_data::from_ptr((&raw mut notifier).cast());

	drop(borrowed_ring);

	unsafe { Pin::new_unchecked(&mut notifier) }.await;
	fut
}

pub async fn fixed_fd_install(
	ring: &RefCell<Uring>,
	fixed_fd: &FixedFd<'_>,
) -> Result<OwnedFd, Errno> {
	let mut sqe = ZERO_SQE;
	sqe.opcode = IoringOp::FixedFdInstall;
	sqe.fd = fixed_fd.fd;
	sqe.flags = IoringSqeFlags::FIXED_FILE;

	let mut op = Op::new();
	Op::init(
		unsafe { Pin::new_unchecked(&mut op) },
		&mut ring.borrow_mut(),
		sqe,
	);

	error_code(unsafe { Pin::new_unchecked(&mut op) }.await.0)
		.map(|raw_fd| unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

pub async fn close(ring: &RefCell<Uring>, fd: OwnedFd) -> Result<(), Errno> {
	let mut sqe = ZERO_SQE;
	sqe.opcode = IoringOp::Close;
	sqe.fd = fd.into_raw_fd();

	let mut op = Op::new();
	Op::init(
		unsafe { Pin::new_unchecked(&mut op) },
		&mut ring.borrow_mut(),
		sqe,
	);

	error_code(unsafe { Pin::new_unchecked(&mut op) }.await.0).map(|_| ())
}

pub async fn close_direct(ring: &RefCell<Uring>, fd: &FixedFd<'_>) -> Result<(), Errno> {
	let mut sqe = ZERO_SQE;
	sqe.opcode = IoringOp::Close;
	sqe.splice_fd_in_or_file_index_or_addr_len = splice_fd_in_or_file_index_or_addr_len_union {
		file_index: fd.fd as u32 + 1,
	};

	let mut op = Op::new();
	Op::init(
		unsafe { Pin::new_unchecked(&mut op) },
		&mut ring.borrow_mut(),
		sqe,
	);

	error_code(unsafe { Pin::new_unchecked(&mut op) }.await.0).map(|_| ())
}

pub async fn openat(
	ring: &RefCell<Uring>,
	dirfd: impl UringFd,
	path: &CStr,
	flags: OFlags,
	mode: Mode,
) -> Result<OwnedFd, Errno> {
	let mut sqe = ZERO_SQE;
	sqe.opcode = IoringOp::Openat;
	sqe.fd = dirfd.fd();
	if dirfd.is_fixed() {
		sqe.flags = IoringSqeFlags::FIXED_FILE;
	}
	sqe.addr_or_splice_off_in = addr_or_splice_off_in_union {
		addr: io_uring_ptr::new(path.as_ptr().cast_mut().cast()),
	};
	sqe.len = len_union {
		len: mode.as_raw_mode(),
	};
	sqe.op_flags = op_flags_union { open_flags: flags };

	let mut op = Op::new();
	Op::init(
		unsafe { Pin::new_unchecked(&mut op) },
		&mut ring.borrow_mut(),
		sqe,
	);

	error_code(unsafe { Pin::new_unchecked(&mut op) }.await.0)
		.map(|raw_fd| unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

pub async fn openat_direct(
	ring: &RefCell<Uring>,
	dirfd: impl UringFd,
	path: &CStr,
	flags: OFlags,
	mode: Mode,
	out_file: &FixedFd<'_>,
) -> Result<(), Errno> {
	let mut sqe = ZERO_SQE;
	sqe.opcode = IoringOp::Openat;
	sqe.fd = dirfd.fd();
	if dirfd.is_fixed() {
		sqe.flags = IoringSqeFlags::FIXED_FILE;
	}
	sqe.addr_or_splice_off_in = addr_or_splice_off_in_union {
		addr: io_uring_ptr::new(path.as_ptr().cast_mut().cast()),
	};
	sqe.len = len_union {
		len: mode.as_raw_mode(),
	};
	sqe.op_flags = op_flags_union { open_flags: flags };
	sqe.splice_fd_in_or_file_index_or_addr_len = splice_fd_in_or_file_index_or_addr_len_union {
		file_index: out_file.fd as u32 + 1,
	};

	let mut op = Op::new();
	Op::init(
		unsafe { Pin::new_unchecked(&mut op) },
		&mut ring.borrow_mut(),
		sqe,
	);

	error_code(unsafe { Pin::new_unchecked(&mut op) }.await.0).map(|_| ())
}

pub async fn openat2(
	ring: &RefCell<Uring>,
	dirfd: impl UringFd,
	path: &CStr,
	how: &open_how,
) -> Result<OwnedFd, Errno> {
	let mut sqe = ZERO_SQE;
	sqe.opcode = IoringOp::Openat2;
	sqe.fd = dirfd.fd();
	if dirfd.is_fixed() {
		sqe.flags = IoringSqeFlags::FIXED_FILE;
	}
	sqe.addr_or_splice_off_in = addr_or_splice_off_in_union {
		addr: io_uring_ptr::from(path.as_ptr().cast_mut().cast()),
	};
	sqe.off_or_addr2 = off_or_addr2_union {
		addr2: io_uring_ptr::from((&raw const *how).cast_mut().cast()),
	};
	sqe.len = len_union {
		len: size_of::<open_how>().try_into().unwrap(),
	};

	let mut op = Op::new();
	Op::init(
		unsafe { Pin::new_unchecked(&mut op) },
		&mut ring.borrow_mut(),
		sqe,
	);

	error_code(unsafe { Pin::new_unchecked(&mut op) }.await.0)
		.map(|raw_fd| unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

pub async fn openat2_direct(
	ring: &RefCell<Uring>,
	dirfd: impl UringFd,
	path: &CStr,
	how: &open_how,
	out_file: &FixedFd<'_>,
) -> Result<(), Errno> {
	let mut sqe = ZERO_SQE;
	sqe.opcode = IoringOp::Openat2;
	sqe.fd = dirfd.fd();
	if dirfd.is_fixed() {
		sqe.flags = IoringSqeFlags::FIXED_FILE;
	}
	sqe.addr_or_splice_off_in = addr_or_splice_off_in_union {
		addr: io_uring_ptr::from(path.as_ptr().cast_mut().cast()),
	};
	sqe.off_or_addr2 = off_or_addr2_union {
		addr2: io_uring_ptr::from((&raw const *how).cast_mut().cast()),
	};
	sqe.len = len_union {
		len: size_of::<open_how>().try_into().unwrap(),
	};
	sqe.splice_fd_in_or_file_index_or_addr_len = splice_fd_in_or_file_index_or_addr_len_union {
		file_index: out_file.fd as u32 + 1,
	};

	let mut op = Op::new();
	Op::init(
		unsafe { Pin::new_unchecked(&mut op) },
		&mut ring.borrow_mut(),
		sqe,
	);

	error_code(unsafe { Pin::new_unchecked(&mut op) }.await.0).map(|_| ())
}

pub async fn statx(
	ring: &RefCell<Uring>,
	dirfd: impl UringFd,
	path: &CStr,
	flags: AtFlags,
	mask: StatxFlags,
) -> Result<Statx, Errno> {
	let mut buf: Statx = unsafe { MaybeUninit::zeroed().assume_init() };

	let mut sqe = ZERO_SQE;
	sqe.opcode = IoringOp::Statx;
	sqe.fd = dirfd.fd();
	if dirfd.is_fixed() {
		sqe.flags = IoringSqeFlags::FIXED_FILE;
	}
	sqe.addr_or_splice_off_in = addr_or_splice_off_in_union {
		addr: io_uring_ptr::from(path.as_ptr().cast_mut().cast()),
	};
	sqe.off_or_addr2 = off_or_addr2_union {
		addr2: io_uring_ptr::from((&raw mut buf).cast()),
	};
	sqe.len = len_union { len: mask.bits() };
	sqe.op_flags = op_flags_union { statx_flags: flags };

	let mut op = Op::new();
	Op::init(
		unsafe { Pin::new_unchecked(&mut op) },
		&mut ring.borrow_mut(),
		sqe,
	);

	error_code(unsafe { Pin::new_unchecked(&mut op) }.await.0).map(|_| buf)
}

#[cfg(test)]
mod test {
	use core::{
		cell::RefCell,
		future::join,
		pin::{Pin, pin},
		task::{Context, Poll, Waker},
	};
	use std::os::fd::{AsRawFd, FromRawFd};

	use rustix::{fs::CWD, io};

	use crate::*;

	fn block_on<F: Future>(ring: &RefCell<Uring>, mut fut: F) -> F::Output {
		loop {
			if let Poll::Ready(x) = Future::poll(
				unsafe { Pin::new_unchecked(&mut fut) },
				&mut Context::from_waker(Waker::noop()),
			) {
				return x;
			}

			ring.borrow_mut().enter(1, None, None).unwrap();
		}
	}

	#[test]
	fn nop() {
		let ring = RefCell::new(Uring::new(1, 0).unwrap());

		let f = ops::nop(&ring);
		eprintln!("{}", core::mem::size_of_val(&f));

		block_on(&ring, f);
	}

	#[test]
	fn link() {
		let ring = RefCell::new(Uring::new(2, 0).unwrap());

		async fn order<F: Future>(f: F, output: &RefCell<Vec<u8>>, val: u8) {
			let _ = f.await;
			output.borrow_mut().push(val);
		}

		block_on(&ring, async {
			let output = RefCell::new(Vec::new());

			{
				let tmp1 = pin!(order(ops::nop(&ring), &output, 0));
				let n1 = ops::link(&ring, tmp1).await;
				let n2 = order(ops::nop(&ring), &output, 1);

				join!(n1, n2).await;
			}
			assert_eq!(output.into_inner(), &[0, 1]);
		});

		block_on(&ring, async {
			let output = RefCell::new(Vec::new());

			{
				let mut n1 = pin!(order(ops::nop(&ring), &output, 0));
				ops::link(&ring, n1.as_mut()).await;
				let mut n2 = pin!(order(ops::nop(&ring), &output, 1));
				ops::link(&ring, n2.as_mut()).await;
				let n3 = order(ops::nop(&ring), &output, 2);

				// n1 and n2 have to be processed in this order because they complete at the same time
				join!(n3, n1, n2).await;
			}
			assert_eq!(output.into_inner(), &[0, 1, 2]);
		});
	}

	#[test]
	fn close() {
		let ring = RefCell::new(Uring::new(1, 0).unwrap());

		let fd = rustix::fs::open("/dev/null", OFlags::RDONLY, Mode::empty()).unwrap();
		let copied_fd = unsafe { OwnedFd::from_raw_fd(fd.as_raw_fd()) };

		block_on(&ring, ops::close(&ring, fd)).unwrap();

		let mut buf = [0];
		assert_eq!(
			rustix::io::read(copied_fd.as_fd(), &mut buf),
			Err(Errno::BADF)
		);
		mem::forget(copied_fd);
	}

	#[test]
	fn close_direct() {
		let ring = RefCell::new(Uring::new(1, 1).unwrap());

		block_on(&ring, async {
			let file = Uring::get_fixed_file(&ring).unwrap();
			ops::openat_direct(
				&ring,
				CWD,
				c"/dev/null",
				OFlags::RDONLY,
				Mode::empty(),
				&file,
			)
			.await
			.unwrap();
			ops::close_direct(&ring, &file).await.unwrap();

			assert_eq!(ops::close_direct(&ring, &file).await, Err(Errno::BADF));
		});
	}

	#[test]
	fn openat() {
		let ring = RefCell::new(Uring::new(1, 1).unwrap());

		let fd = block_on(&ring, async {
			ops::openat(&ring, CWD, c"/dev/zero", OFlags::RDONLY, Mode::empty())
				.await
				.unwrap()
		});

		let mut buf = [1u8; 64];
		io::read(fd, &mut buf).unwrap();
		assert_eq!(buf, [0u8; 64]);
	}

	#[test]
	fn openat_direct() {
		let ring = RefCell::new(Uring::new(1, 1).unwrap());

		let file = Uring::get_fixed_file(&ring).unwrap();
		let regular_fd = block_on(&ring, async {
			ops::openat_direct(
				&ring,
				CWD,
				c"/dev/zero",
				OFlags::RDONLY,
				Mode::empty(),
				&file,
			)
			.await
			.unwrap();

			ops::fixed_fd_install(&ring, &file).await.unwrap()
		});

		let mut buf = [1u8; 64];
		io::read(regular_fd, &mut buf).unwrap();
		assert_eq!(buf, [0u8; 64]);
	}

	#[test]
	fn openat2() {
		let ring = RefCell::new(Uring::new(1, 0).unwrap());

		let mut how = open_how::default();
		how.flags = OFlags::RDONLY.bits().into();
		how.mode = 0;
		how.resolve = ResolveFlags::empty();

		let fd = block_on(&ring, async {
			ops::openat2(&ring, CWD, c"/dev/zero", &how).await.unwrap()
		});

		let mut buf = [1u8; 64];
		io::read(fd, &mut buf).unwrap();
		assert_eq!(buf, [0u8; 64]);
	}

	#[test]
	fn openat2_direct() {
		let ring = RefCell::new(Uring::new(1, 1).unwrap());

		let file = Uring::get_fixed_file(&ring).unwrap();
		let mut how = open_how::default();
		how.flags = OFlags::RDONLY.bits().into();
		how.mode = 0;
		how.resolve = ResolveFlags::empty();

		let regular_fd = block_on(&ring, async {
			ops::openat2_direct(&ring, CWD, c"/dev/zero", &how, &file)
				.await
				.unwrap();

			ops::fixed_fd_install(&ring, &file).await.unwrap()
		});

		let mut buf = [1u8; 64];
		io::read(regular_fd, &mut buf).unwrap();
		assert_eq!(buf, [0u8; 64]);
	}

	#[test]
	fn statx() {
		let ring = RefCell::new(Uring::new(1, 0).unwrap());

		let statx = block_on(
			&ring,
			ops::statx(
				&ring,
				CWD,
				c"/dev/null",
				AtFlags::empty(),
				StatxFlags::BASIC_STATS,
			),
		)
		.unwrap();

		assert_eq!(statx.stx_rdev_major, 1);
		assert_eq!(statx.stx_rdev_minor, 3);
	}
}
