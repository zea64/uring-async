#![allow(clippy::tabs_in_doc_comments)]

use core::{
	cell::RefCell,
	cmp::min,
	ffi::c_void,
	mem::{self, MaybeUninit},
	ptr::{self, NonNull},
	slice,
	time::Duration,
};

use fd::*;
use rustix::{
	fd::{AsFd, OwnedFd},
	io::Errno,
	io_uring::*,
	mm::{MapFlags, ProtFlags, mmap, munmap},
};

pub mod fd;
pub mod ops;

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
	in_flight: u32,
	fixed_files: FixedFileSet,
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

	pub fn new(entries: u32, fixed_files: u32) -> Result<Self, Errno> {
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

		let fixed_files = unsafe { FixedFileSet::new(fd.as_fd(), fixed_files) }?;

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
			in_flight: 0,
			fixed_files,
		})
	}

	/// # Safety
	/// `sqe` sends low level commands to the kernel that, for instance, can read and write to arbitrary memory. Consult the safety conditions of the underlying io_uring operations and corresponding syscalls.
	pub unsafe fn push(&mut self, sqe: Sqe) -> Result<(), Errno> {
		let sqe = sqe.into();

		while self.sq().push(sqe).is_err() {
			self.enter(0, None, None)?;
		}

		Ok(())
	}

	pub fn enter(
		&mut self,
		min_complete: u32,
		min_wait: Option<Duration>,
		timeout: Option<Duration>,
	) -> Result<u32, Errno> {
		let min_wait = min_wait
			.map(|mw| match mw.as_micros() {
				t if t > u32::MAX as u128 => u32::MAX,
				t => t as u32,
			})
			.unwrap_or_default();

		let timeout = timeout.map(|t| Timespec {
			tv_sec: t.as_secs() as i64,
			tv_nsec: (t.as_nanos() % 1_000_000_000) as i64,
		});

		let args = io_uring_getevents_arg {
			sigmask: io_uring_ptr::null(),
			sigmask_sz: 0,
			min_wait_usec: min_wait,
			ts: io_uring_ptr::new(
				timeout
					.map(|mut t| &raw mut t)
					.unwrap_or(ptr::null_mut())
					.cast(),
			),
		};

		let to_sumbit = self.sq().len();
		self.in_flight += to_sumbit;

		let submitted = unsafe {
			io_uring_enter_arg(
				self.fd.as_fd(),
				to_sumbit,
				min(min_complete, self.in_flight),
				IoringEnterFlags::GETEVENTS | IoringEnterFlags::EXT_ARG,
				Some(&args),
			)
		}?;

		while let Some(cqe) = self.cq().pop() {
			let ptr: *mut () = cqe.user_data.ptr().cast();

			if let Some(callback) = unsafe { &*ptr.cast::<CompletionCallback>() } {
				self.in_flight -= unsafe { (callback)(ptr, cqe) } as u32;
			} else {
				self.in_flight -= 1;
			}
		}

		Ok(submitted)
	}

	pub fn get_fixed_file<'a>(this: &'a RefCell<Self>) -> Option<FixedFd<'a>> {
		Some(FixedFd {
			ring: this,
			fd: this.borrow_mut().fixed_files.alloc()?.try_into().unwrap(),
		})
	}

	/// # Safety
	/// Callers must pass only values obtained from [`Uring::get_fixed_file`] and do so at most once. Same rules as memory deallocation.
	unsafe fn return_fixed_file(&mut self, file: u32) {
		self.fixed_files.dealloc(file)
	}
}

pub type CompletionCallback = Option<unsafe fn(*mut (), io_uring_cqe) -> bool>;

pub struct Sqe(io_uring_sqe);

impl Sqe {
	/// # Safety
	/// `callback` must point to a valid function pointer of type `CompletionCallback`.
	/// Usually, you will use it like this:
	/// ```rs
	/// #[repr(C)]
	/// struct Foo {
	/// 	callback: CompletionCallback,
	/// 	other_stuff: blah,
	/// }
	/// ```
	/// and cast a pointer to `Foo` into a pointer to `CompletionCallback`.
	pub unsafe fn new(mut sqe: io_uring_sqe, callback: NonNull<CompletionCallback>) -> Self {
		sqe.user_data.ptr.ptr = callback.as_ptr().cast();
		Self(sqe)
	}
}

impl From<Sqe> for io_uring_sqe {
	fn from(value: Sqe) -> Self {
		value.0
	}
}

#[cfg(test)]
mod test {
	use core::{
		future::Future,
		pin::Pin,
		task::{Context, Poll, Waker},
	};

	use crate::{ops::*, *};

	#[test]
	fn low_level_ring_works() {
		let mut ring = Uring::new(64, 0).unwrap();
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

	#[test]
	fn op_works() {
		let mut ring = Uring::new(64, 0).unwrap();

		let mut sqe: io_uring_sqe = unsafe { MaybeUninit::zeroed().assume_init() };
		sqe.opcode = IoringOp::Nop;

		let mut op = Op::new();
		Op::init(unsafe { Pin::new_unchecked(&mut op) }, &mut ring, sqe);

		ring.enter(1, None, None).unwrap();

		let res = Future::poll(
			unsafe { Pin::new_unchecked(&mut op) },
			&mut Context::from_waker(Waker::noop()),
		);
		assert_eq!(res, Poll::Ready((0, IoringCqeFlags::empty())));
	}
}
