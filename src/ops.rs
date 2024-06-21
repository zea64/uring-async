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
	fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd},
	fs::{self, AtFlags, StatxFlags},
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

#[derive(Debug)]
pub struct Op<'a> {
	ring: &'a RefCell<Uring>,
	ticket: NonZeroU64,
}

impl<'a> Op<'a> {
	pub fn new(ring: &'a RefCell<Uring>, mut sqe: Sqe) -> Self {
		let mut unlocked_ring = ring.borrow_mut();
		let ticket = unlocked_ring.get_ticket();
		sqe.user_data = io_uring_user_data::from_u64(ticket.into());
		unlocked_ring.push(sqe).unwrap();
		Op { ring, ticket }
	}
}

impl<'a> Future for Op<'a> {
	type Output = Cqe;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = Pin::into_inner(self);
		let mut ring = this.ring.borrow_mut();
		match ring.poll(this.ticket.into(), Some(cx)) {
			Some(cqe) => Poll::Ready(cqe),
			None => Poll::Pending,
		}
	}
}

#[derive(Debug)]
pub struct Nop<'a> {
	op: Op<'a>,
}

impl<'a> Future for Nop<'a> {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		Future::poll(Pin::new(&mut Pin::into_inner(self).op), cx).map(|_cqe| ())
	}
}

impl<'a> Nop<'a> {
	pub fn new(ring: &'a RefCell<Uring>) -> Self {
		Nop {
			op: Op::new(ring, unsafe { Sqe::new(zero!()) }),
		}
	}
}

#[derive(Debug)]
pub struct Close<'a> {
	op: Op<'a>,
}

impl<'a> Future for Close<'a> {
	type Output = PosixResult<()>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		Future::poll(Pin::new(&mut Pin::into_inner(self).op), cx)
			.map(|cqe| res_or_errno(cqe.res).map(|_res| ()))
	}
}

impl<'a> Close<'a> {
	pub fn new(ring: &'a RefCell<Uring>, fd: OwnedFd) -> Self {
		Close {
			op: Op::new(ring, unsafe {
				Sqe::new(io_uring_sqe {
					opcode: IoringOp::Close,
					flags: IoringSqeFlags::empty(),
					ioprio: zero!(),
					fd: fd.into_raw_fd(),
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
			}),
		}
	}
}

#[derive(Debug)]
pub struct Openat2<'a> {
	op: Op<'a>,
}

impl<'a> Future for Openat2<'a> {
	type Output = PosixResult<OwnedFd>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		Future::poll(Pin::new(&mut Pin::into_inner(self).op), cx)
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
			op: Op::new(ring, unsafe {
				Sqe::new(io_uring_sqe {
					opcode: IoringOp::Openat2,
					flags: sqe_flags,
					ioprio: zero!(),
					fd: dfd.as_raw_fd(),
					off_or_addr2: off_or_addr2_union {
						addr2: io_uring_ptr::from(open_how as *const _ as *mut c_void),
					},
					addr_or_splice_off_in: addr_or_splice_off_in_union {
						addr: io_uring_ptr::from(path.as_ptr() as *mut c_void),
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
			}),
		}
	}
}

#[derive(Debug)]
pub struct Read<'a> {
	op: Op<'a>,
	buf: *mut u8,
}

impl<'a> Future for Read<'a> {
	type Output = PosixResult<&'a mut [u8]>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = Pin::into_inner(self);
		Future::poll(Pin::new(&mut this.op), cx).map(|cqe| {
			res_or_errno(cqe.res).map(|len| unsafe {
				core::slice::from_raw_parts_mut(this.buf, len.try_into().unwrap())
			})
		})
	}
}

impl<'a> Read<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		fd: BorrowedFd<'a>,
		buf: &'a mut [MaybeUninit<u8>],
		sqe_flags: IoringSqeFlags,
	) -> Self {
		Read {
			op: Op::new(ring, unsafe {
				Sqe::new(io_uring_sqe {
					opcode: IoringOp::Read,
					flags: sqe_flags,
					ioprio: zero!(),
					fd: fd.as_raw_fd(),
					off_or_addr2: off_or_addr2_union { off: u64::MAX },
					addr_or_splice_off_in: addr_or_splice_off_in_union {
						addr: io_uring_ptr::from(buf.as_mut_ptr().cast()),
					},
					len: len_union {
						len: buf.len() as u32,
					},
					op_flags: zero!(),
					user_data: zero!(),
					buf: zero!(),
					personality: zero!(),
					splice_fd_in_or_file_index: zero!(),
					addr3_or_cmd: zero!(),
				})
			}),
			buf: buf.as_mut_ptr().cast(),
		}
	}
}

#[derive(Debug)]
pub struct Statx<'a> {
	op: Op<'a>,
	buf: *mut fs::Statx,
}

impl<'a> Future for Statx<'a> {
	type Output = PosixResult<&'a mut fs::Statx>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = Pin::into_inner(self);
		Future::poll(Pin::new(&mut this.op), cx)
			.map(|cqe| res_or_errno(cqe.res).map(|_res| unsafe { &mut *this.buf }))
	}
}

impl<'a> Statx<'a> {
	pub fn new(
		ring: &'a RefCell<Uring>,
		dfd: BorrowedFd<'a>,
		path: &'a CStr,
		flags: AtFlags,
		mask: StatxFlags,
		buf: &'a mut MaybeUninit<fs::Statx>,
		sqe_flags: IoringSqeFlags,
	) -> Self {
		Statx {
			op: Op::new(ring, unsafe {
				Sqe::new(io_uring_sqe {
					opcode: IoringOp::Statx,
					flags: sqe_flags,
					ioprio: zero!(),
					fd: dfd.as_raw_fd(),
					off_or_addr2: off_or_addr2_union {
						addr2: io_uring_ptr::from(buf.as_ptr() as *mut c_void),
					},
					addr_or_splice_off_in: addr_or_splice_off_in_union {
						addr: io_uring_ptr::from(path.as_ptr() as *mut c_void),
					},
					len: len_union { len: mask.bits() },
					op_flags: op_flags_union { statx_flags: flags },
					user_data: zero!(),
					buf: zero!(),
					personality: zero!(),
					splice_fd_in_or_file_index: zero!(),
					addr3_or_cmd: zero!(),
				})
			}),
			buf: buf.as_mut_ptr().cast(),
		}
	}
}

#[cfg(test)]
mod test {
	use core::cell::RefCell;

	use rustix::{
		fd::AsFd,
		fs::{self, ResolveFlags},
	};

	use crate::{ops::*, test::block_on};

	#[test]
	fn nop() {
		let ring = RefCell::new(Uring::new().unwrap());

		let nop = Nop::new(&ring);

		block_on(&ring, nop);
	}

	#[test]
	fn close() {
		let ring = RefCell::new(Uring::new().unwrap());

		let fd = fs::open("/dev/null", OFlags::empty(), Mode::empty()).unwrap();
		block_on(&ring, Close::new(&ring, fd)).unwrap();
	}

	#[test]
	fn openat2() {
		let ring = RefCell::new(Uring::new().unwrap());

		let fd = block_on(
			&ring,
			Openat2::new(
				&ring,
				fs::CWD,
				CStr::from_bytes_with_nul(b"/dev/zero\0").unwrap(),
				&open_how {
					flags: OFlags::RDONLY.bits() as u64,
					mode: 0,
					resolve: ResolveFlags::empty(),
				},
				IoringSqeFlags::empty(),
			),
		)
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
		let mut buf = [MaybeUninit::uninit(); 64];

		let result = block_on(
			&ring,
			Read::new(&ring, fd.as_fd(), &mut buf, IoringSqeFlags::empty()),
		)
		.unwrap();
		assert_eq!(result, [0u8; 64]);
	}

	#[test]
	fn statx() {
		let ring = RefCell::new(Uring::new().unwrap());

		let mut buf = MaybeUninit::uninit();

		let stat = block_on(
			&ring,
			Statx::new(
				&ring,
				fs::CWD,
				CStr::from_bytes_with_nul(b"/dev/zero\0").unwrap(),
				AtFlags::empty(),
				StatxFlags::ALL,
				&mut buf,
				IoringSqeFlags::empty(),
			),
		)
		.unwrap();

		assert_eq!(stat.stx_rdev_major, 1);
		assert_eq!(stat.stx_rdev_minor, 5);
	}
}
