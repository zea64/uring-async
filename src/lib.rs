use core::{
	error::Error,
	ffi::c_void,
	fmt,
	mem::{self, MaybeUninit},
	ptr::{self, NonNull},
	slice,
};
use std::os::fd::AsFd;

use rustix::{
	fd::OwnedFd,
	io::Errno,
	io_uring::*,
	mm::{MapFlags, ProtFlags, mmap, munmap},
};

#[derive(Debug)]
struct Mmapped(NonNull<c_void>, usize);

impl Mmapped {
	unsafe fn new(ptr: *mut c_void, size: usize) -> Self {
		Self(NonNull::new(ptr).unwrap(), size)
	}

	fn as_ptr(&self) -> *mut c_void {
		self.0.as_ptr()
	}
}

impl Drop for Mmapped {
	fn drop(&mut self) {
		let _ = unsafe { munmap(self.0.as_ptr(), self.1) };
	}
}

#[derive(Debug)]
struct RingBuffer<'a, T> {
	ring: &'a mut [MaybeUninit<T>],
	head: &'a mut u32,
	tail: &'a mut u32,
}

impl<T> RingBuffer<'_, T> {
	fn push(&mut self, input: T) -> Result<(), T> {
		if self.len() == self.capacity() {
			return Err(input);
		}

		self.index_mut(*self.tail).write(input);
		*self.tail += 1;
		Ok(())
	}

	fn pop(&mut self) -> Option<T> {
		if self.len() == 0 {
			return None;
		}

		let value = unsafe { self.index_mut(*self.head).assume_init_read() };
		*self.head += 1;
		Some(value)
	}

	#[inline]
	fn len(&self) -> u32 {
		let diff = *self.tail - *self.head;
		assert!(diff <= self.capacity());
		diff
	}

	#[inline]
	fn capacity(&self) -> u32 {
		self.ring.len() as u32
	}

	#[inline]
	fn index_mut(&mut self, idx: u32) -> &mut MaybeUninit<T> {
		let idx = idx & (self.capacity() - 1);
		unsafe { self.ring.get_unchecked_mut(idx as usize) }
	}
}

#[derive(Debug, Clone, Copy)]
pub struct QueueFullError;

impl Error for QueueFullError {}

impl fmt::Display for QueueFullError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("io_uring submission queue full")
	}
}

#[derive(Debug)]
pub struct Uring {
	cq_mmap: Mmapped,
	sq_mmap: Mmapped,
	fd: OwnedFd,
	cq_head_off: u32,
	cq_tail_off: u32,
	cq_cqes_off: u32,
	cq_size: u32,
	sq_head_off: u32,
	sq_tail_off: u32,
	sq_size: u32,
}

impl Uring {
	fn cq(&mut self) -> RingBuffer<'_, io_uring_cqe> {
		unsafe {
			let base: *mut u32 = self.cq_mmap.as_ptr().cast();
			let ring = slice::from_raw_parts_mut(
				base.byte_offset(self.cq_cqes_off.try_into().unwrap())
					.cast(),
				self.cq_size.try_into().unwrap(),
			);
			let head = &mut *base.byte_offset(self.cq_head_off.try_into().unwrap());
			let tail = &mut *base.byte_offset(self.cq_tail_off.try_into().unwrap());
			RingBuffer { ring, head, tail }
		}
	}

	fn sq(&mut self) -> RingBuffer<'_, io_uring_sqe> {
		unsafe {
			let ring = slice::from_raw_parts_mut(
				self.sq_mmap.as_ptr().cast(),
				self.sq_size.try_into().unwrap(),
			);

			let base: *mut u32 = self.cq_mmap.as_ptr().cast();
			let head = &mut *base.byte_offset(self.sq_head_off.try_into().unwrap());
			let tail = &mut *base.byte_offset(self.sq_tail_off.try_into().unwrap());
			RingBuffer { ring, head, tail }
		}
	}

	pub fn new(entries: u32) -> Result<Self, Errno> {
		let mut params = io_uring_params::default();
		params.flags = IoringSetupFlags::CLAMP
			| IoringSetupFlags::SUBMIT_ALL
			| IoringSetupFlags::COOP_TASKRUN
			| IoringSetupFlags::SINGLE_ISSUER
			| IoringSetupFlags::DEFER_TASKRUN
			| IoringSetupFlags::NO_SQARRAY;

		let fd = unsafe { io_uring_setup(entries.next_power_of_two(), &mut params) }?;
		if !params.features.contains(
			IoringFeatureFlags::SINGLE_MMAP
				| IoringFeatureFlags::NODROP
				| IoringFeatureFlags::LINKED_FILE,
		) {
			return Err(Errno::NOSYS);
		}

		let cq_size = params.cq_off.cqes as usize
			+ params.cq_entries as usize * mem::size_of::<io_uring_cqe>();
		let sq_size = params.sq_entries as usize * mem::size_of::<io_uring_sqe>();

		let cq_mmap = unsafe {
			Mmapped::new(
				mmap(
					ptr::null_mut(),
					cq_size,
					ProtFlags::READ | ProtFlags::WRITE,
					MapFlags::POPULATE | MapFlags::SHARED_VALIDATE,
					fd.as_fd(),
					IORING_OFF_SQ_RING,
				)?,
				cq_size,
			)
		};

		let sq_mmap = unsafe {
			Mmapped::new(
				mmap(
					ptr::null_mut(),
					sq_size,
					ProtFlags::READ | ProtFlags::WRITE,
					MapFlags::POPULATE | MapFlags::SHARED_VALIDATE,
					fd.as_fd(),
					IORING_OFF_SQES,
				)?,
				sq_size,
			)
		};

		assert!(params.cq_entries.is_power_of_two());
		assert!(params.sq_entries.is_power_of_two());

		Ok(Uring {
			fd,
			cq_mmap,
			sq_mmap,
			cq_head_off: params.cq_off.head,
			cq_tail_off: params.cq_off.tail,
			cq_cqes_off: params.cq_off.cqes,
			cq_size: params.cq_entries,
			sq_head_off: params.sq_off.head,
			sq_tail_off: params.sq_off.tail,
			sq_size: params.sq_entries,
		})
	}

	/// # Safety
	/// `sqe` sends low level commands to the kernel that, for instance, can read and write to arbitrary memory. Consult the safety conditions of the underlying io_uring operations and corresponding syscalls.
	pub unsafe fn push(&mut self, sqe: io_uring_sqe) -> Result<(), QueueFullError> {
		self.sq().push(sqe).map_err(|_| QueueFullError)
	}

	pub fn pop(&mut self) -> Option<io_uring_cqe> {
		self.cq().pop()
	}
}

#[cfg(test)]
mod test {
	use crate::*;

	#[test]
	fn basic() {
		let mut ring = Uring::new(64).unwrap();
		let mut sq = ring.sq();

		for i in 0.. {
			let mut nop: io_uring_sqe = unsafe { MaybeUninit::zeroed().assume_init() };
			nop.opcode = IoringOp::Nop;
			nop.user_data.u64_ = i;

			if sq.push(nop).is_err() {
				break;
			}
		}

		let len = ring.sq().len();
		let res = unsafe { io_uring_enter(ring.fd.as_fd(), len, len, IoringEnterFlags::GETEVENTS) }
			.unwrap();
		assert_eq!(res, 64);

		let mut cq = ring.cq();
		for i in 0..64 {
			let cqe = cq.pop().unwrap();
			assert_eq!(cqe.user_data.u64_(), i);
		}
		assert!(cq.pop().is_none());
	}
}
