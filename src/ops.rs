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
	fd::{FromRawFd, OwnedFd},
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

#[cfg(test)]
mod test {
	use core::{
		cell::RefCell,
		pin::Pin,
		task::{Context, Poll, Waker},
	};

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
}
