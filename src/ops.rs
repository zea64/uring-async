use core::{
	cell::RefCell,
	ffi::CStr,
	future::Future,
	mem::MaybeUninit,
	num::NonZeroU64,
	pin::Pin,
	task::{Context, Poll},
};

use rustix::{
	fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
	fs::{self, AtFlags, Mode, OFlags, StatxFlags},
	io::Errno,
	io_uring::*,
};

use crate::*;

macro_rules! zero {
	() => {
		MaybeUninit::zeroed().assume_init()
	};
}

fn res_or_errno(result: i32) -> Result<i32, Errno> {
	match result {
		x if x < 0 => Err(Errno::from_raw_os_error(-x)),
		x => Ok(x),
	}
}

pub struct Op<'a> {
	ring: &'a RefCell<Uring>,
	ticket: Option<NonZeroU64>,
}

impl<'a> Op<'a> {
	pub fn new(ring: &'a RefCell<Uring>) -> Self {
		Op { ring, ticket: None }
	}
}

impl<'a> Op<'a> {
	pub fn poll(&mut self, cx: &mut Context<'_>, sqe_factory: impl FnOnce() -> Sqe) -> Poll<Cqe> {
		let mut ring = match self.ring.try_borrow_mut() {
			Ok(x) => x,
			Err(_) => {
				cx.waker().wake_by_ref();
				return Poll::Pending;
			}
		};

		if let Some(ticket) = self.ticket {
			return match ring.get_cqe(ticket.into()) {
				Some(cqe) => Poll::Ready(cqe),
				None => {
					ring.want_submit().unwrap();
					cx.waker().wake_by_ref();
					Poll::Pending
				}
			};
		}

		let ticket = ring.get_ticket();
		self.ticket = Some(ticket);

		ring.push(sqe_factory().set_user_data(ticket.into()))
			.unwrap();

		cx.waker().wake_by_ref();

		Poll::Pending
	}
}

pub struct Nop<'a> {
	op: Op<'a>,
}

impl<'a> Future for Nop<'a> {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		Pin::into_inner(self)
			.op
			.poll(cx, || unsafe { Sqe::new(zero!()) })
			.map(|_cqe| ())
	}
}

impl<'a> Nop<'a> {
	pub fn new(ring: &'a RefCell<Uring>) -> Self {
		Nop { op: Op::new(ring) }
	}
}

pub struct Openat<'a> {
	op: Op<'a>,
	dfd: BorrowedFd<'a>,
	path: &'a CStr,
	flags: OFlags,
	mode: Mode,
	sqe_flags: IoringSqeFlags,
}

impl<'a> Future for Openat<'a> {
	type Output = PosixResult<OwnedFd>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = Pin::into_inner(self);
		let sqe_factory = || unsafe {
			Sqe::new(io_uring_sqe {
				opcode: IoringOp::Openat,
				flags: this.sqe_flags,
				ioprio: zero!(),
				fd: this.dfd.as_raw_fd(),
				off_or_addr2: zero!(),
				addr_or_splice_off_in: addr_or_splice_off_in_union {
					addr: io_uring_ptr::from(this.path.as_ptr() as *mut c_void),
				},
				len: len_union {
					len: this.mode.bits(),
				},
				op_flags: op_flags_union {
					open_flags: this.flags,
				},
				user_data: zero!(),
				buf: zero!(),
				personality: zero!(),
				splice_fd_in_or_file_index: zero!(),
				addr3_or_cmd: zero!(),
			})
		};

		this.op
			.poll(cx, sqe_factory)
			.map(|cqe| res_or_errno(cqe.res).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }))
	}
}

impl<'a> Openat<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		dfd: BorrowedFd<'a>,
		path: &'a CStr,
		flags: OFlags,
		mode: Mode,
		sqe_flags: IoringSqeFlags,
	) -> Self {
		Openat {
			op: Op::new(ring),
			dfd,
			path,
			flags,
			mode,
			sqe_flags,
		}
	}
}

pub struct Openat2<'a> {
	op: Op<'a>,
	dfd: BorrowedFd<'a>,
	path: &'a CStr,
	open_how: &'a open_how,
	sqe_flags: IoringSqeFlags,
}

impl<'a> Future for Openat2<'a> {
	type Output = PosixResult<OwnedFd>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = Pin::into_inner(self);
		let sqe_factory = || unsafe {
			Sqe::new(io_uring_sqe {
				opcode: IoringOp::Openat2,
				flags: this.sqe_flags,
				ioprio: zero!(),
				fd: this.dfd.as_raw_fd(),
				off_or_addr2: off_or_addr2_union {
					addr2: io_uring_ptr::from(this.open_how as *const _ as *mut c_void),
				},
				addr_or_splice_off_in: addr_or_splice_off_in_union {
					addr: io_uring_ptr::from(this.path.as_ptr() as *mut c_void),
				},
				len: len_union {
					len: size_of::<open_how>() as u32,
				},
				op_flags: zero!(),
				user_data: zero!(),
				buf: zero!(),
				personality: zero!(),
				splice_fd_in_or_file_index: zero!(),
				addr3_or_cmd: zero!(),
			})
		};

		this.op
			.poll(cx, sqe_factory)
			.map(|cqe| res_or_errno(cqe.res).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }))
	}
}

impl<'a> Openat2<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		dfd: BorrowedFd<'a>,
		path: &'a CStr,
		open_how: &'a open_how,
		sqe_flags: IoringSqeFlags,
	) -> Self {
		Openat2 {
			op: Op::new(ring),
			dfd,
			path,
			open_how,
			sqe_flags,
		}
	}
}

pub struct Read<'a> {
	op: Op<'a>,
	buf: &'a mut [u8],
	fd: BorrowedFd<'a>,
	sqe_flags: IoringSqeFlags,
}

impl<'a> Future for Read<'a> {
	type Output = PosixResult<i32>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = Pin::into_inner(self);
		let sqe_factory = || unsafe {
			Sqe::new(io_uring_sqe {
				opcode: IoringOp::Read,
				flags: this.sqe_flags,
				ioprio: zero!(),
				fd: this.fd.as_raw_fd(),
				off_or_addr2: off_or_addr2_union { off: u64::MAX },
				addr_or_splice_off_in: addr_or_splice_off_in_union {
					addr: io_uring_ptr::from(this.buf.as_mut_ptr().cast()),
				},
				len: len_union {
					len: this.buf.len() as u32,
				},
				op_flags: zero!(),
				user_data: zero!(),
				buf: zero!(),
				personality: zero!(),
				splice_fd_in_or_file_index: zero!(),
				addr3_or_cmd: zero!(),
			})
		};

		this.op
			.poll(cx, sqe_factory)
			.map(|cqe| res_or_errno(cqe.res))
	}
}

impl<'a> Read<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		fd: BorrowedFd<'a>,
		buf: &'a mut [u8],
		sqe_flags: IoringSqeFlags,
	) -> Self {
		Read {
			op: Op::new(ring),
			buf,
			fd,
			sqe_flags,
		}
	}
}

pub struct Statx<'a> {
	op: Op<'a>,
	dfd: BorrowedFd<'a>,
	path: &'a CStr,
	flags: AtFlags,
	mask: StatxFlags,
	sqe_flags: IoringSqeFlags,
	statx: MaybeUninit<fs::Statx>,
}

impl<'a> Future for Statx<'a> {
	type Output = PosixResult<fs::Statx>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = Pin::into_inner(self);
		let sqe_factory = || unsafe {
			Sqe::new(io_uring_sqe {
				opcode: IoringOp::Statx,
				flags: this.sqe_flags,
				ioprio: zero!(),
				fd: this.dfd.as_raw_fd(),
				off_or_addr2: off_or_addr2_union {
					addr2: io_uring_ptr::from(this.statx.as_ptr() as *mut c_void),
				},
				addr_or_splice_off_in: addr_or_splice_off_in_union {
					addr: io_uring_ptr::from(this.path.as_ptr() as *mut c_void),
				},
				len: len_union {
					len: this.mask.bits(),
				},
				op_flags: op_flags_union {
					statx_flags: this.flags,
				},
				user_data: zero!(),
				buf: zero!(),
				personality: zero!(),
				splice_fd_in_or_file_index: zero!(),
				addr3_or_cmd: zero!(),
			})
		};

		this.op
			.poll(cx, sqe_factory)
			.map(|cqe| res_or_errno(cqe.res).map(|_res| unsafe { this.statx.assume_init() }))
	}
}

impl<'a> Statx<'a> {
	fn new(
		ring: &'a RefCell<Uring>,
		dfd: BorrowedFd<'a>,
		path: &'a CStr,
		flags: AtFlags,
		mask: StatxFlags,
		sqe_flags: IoringSqeFlags,
	) -> Self {
		Statx {
			op: Op::new(ring),
			dfd,
			path,
			flags,
			mask,
			sqe_flags,
			statx: MaybeUninit::zeroed(),
		}
	}
}

pub struct Close<'a> {
	op: Op<'a>,
	fd: RawFd,
}

impl<'a> Future for Close<'a> {
	type Output = PosixResult<()>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = Pin::into_inner(self);
		let sqe_factory = || unsafe {
			Sqe::new(io_uring_sqe {
				opcode: IoringOp::Close,
				flags: IoringSqeFlags::empty(),
				ioprio: zero!(),
				fd: this.fd,
				off_or_addr2: zero!(),
				addr_or_splice_off_in: zero!(),
				len: zero!(),
				op_flags: zero!(),
				user_data: zero!(),
				buf: zero!(),
				personality: zero!(),
				splice_fd_in_or_file_index: zero!(),
				addr3_or_cmd: zero!(),
			})
		};

		this.op
			.poll(cx, sqe_factory)
			.map(|cqe| res_or_errno(cqe.res).map(|_res| ()))
	}
}

impl<'a> Close<'a> {
	pub fn new(ring: &'a RefCell<Uring>, fd: OwnedFd) -> Self {
		Close {
			op: Op::new(ring),
			fd: fd.into_raw_fd(),
		}
	}
}

#[cfg(test)]
mod test {
	use core::{cell::RefCell, future::join};

	use futures::executor::block_on;
	use rustix::{
		fd::AsFd,
		fs::{self, ResolveFlags},
	};

	use crate::ops::*;

	#[test]
	fn nop() {
		let ring = RefCell::new(Uring::new().unwrap());

		let nop = Nop::new(&ring);

		block_on(nop);
	}

	#[test]
	fn two_nops() {
		let ring = RefCell::new(Uring::new().unwrap());

		let nop1 = Nop::new(&ring);
		let nop2 = Nop::new(&ring);

		block_on(join!(nop1, nop2));
	}

	#[test]
	fn async_fn() {
		async fn foo(ring: &RefCell<Uring>) {
			println!("1");
			let _ = Nop::new(ring).await;
			println!("2");
			let _ = Nop::new(ring).await;
			println!("3");
		}

		let ring = RefCell::new(Uring::new().unwrap());

		block_on(foo(&ring));
	}

	#[test]
	fn two_async_fns() {
		async fn foo(ring: &RefCell<Uring>) {
			println!("1");
			let _ = Nop::new(ring).await;
			println!("2");
			let _ = Nop::new(ring).await;
			println!("3");
		}

		let ring = RefCell::new(Uring::new().unwrap());

		block_on(join!(foo(&ring), foo(&ring)));
	}

	#[test]
	fn openat() {
		let ring = RefCell::new(Uring::new().unwrap());

		let fd = block_on(Openat::new(
			&ring,
			rustix::fs::CWD,
			CStr::from_bytes_with_nul(b"/dev/zero\0").unwrap(),
			OFlags::RDONLY,
			Mode::empty(),
			IoringSqeFlags::empty(),
		))
		.unwrap();

		let mut buf = [1u8; 64];

		let result = rustix::io::read(fd, &mut buf);
		assert_eq!(result, Ok(64));
		assert_eq!(buf, [0u8; 64]);
	}

	#[test]
	fn openat2() {
		let ring = RefCell::new(Uring::new().unwrap());

		let fd = block_on(Openat2::new(
			&ring,
			fs::CWD,
			CStr::from_bytes_with_nul(b"/dev/zero\0").unwrap(),
			&open_how {
				flags: OFlags::RDONLY.bits() as u64,
				mode: 0,
				resolve: ResolveFlags::empty(),
			},
			IoringSqeFlags::empty(),
		))
		.unwrap();

		let mut buf = [1u8; 64];

		let result = rustix::io::read(fd, &mut buf);
		assert_eq!(result, Ok(64));
		assert_eq!(buf, [0u8; 64]);
	}

	#[test]
	fn read() {
		let ring = RefCell::new(Uring::new().unwrap());

		let fd = fs::open("/dev/zero", OFlags::empty(), Mode::empty()).unwrap();
		let mut buf = [1u8; 64];

		let result = block_on(Read::new(
			&ring,
			fd.as_fd(),
			&mut buf,
			IoringSqeFlags::empty(),
		));
		assert_eq!(result, Ok(64));
		assert_eq!(buf, [0u8; 64]);
	}

	#[test]
	fn statx() {
		let ring = RefCell::new(Uring::new().unwrap());

		let stat = block_on(Statx::new(
			&ring,
			fs::CWD,
			CStr::from_bytes_with_nul(b"/dev/zero\0").unwrap(),
			AtFlags::empty(),
			StatxFlags::ALL,
			IoringSqeFlags::empty(),
		))
		.unwrap();

		assert_eq!(stat.stx_rdev_major, 1);
		assert_eq!(stat.stx_rdev_minor, 5);
	}

	#[test]
	fn close() {
		let ring = RefCell::new(Uring::new().unwrap());

		let fd = fs::open("/dev/null", OFlags::empty(), Mode::empty()).unwrap();
		block_on(Close::new(&ring, fd)).unwrap();
	}
}
