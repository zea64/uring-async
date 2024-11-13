#![feature(future_join, noop_waker)]

pub mod ops;
pub mod sync;

use core::{
	cell::RefCell,
	ffi::c_void,
	fmt::{self, Debug},
	future::Future,
	mem::size_of,
	num::NonZeroU64,
	ops::{Deref, DerefMut, Rem},
	pin::Pin,
	ptr::{self, NonNull},
	task::{Context, Poll, Waker},
};
use std::collections::HashMap;

use rustix::{
	fd::OwnedFd,
	io::{Errno, Result as PosixResult},
	io_uring::*,
	mm::{mmap, munmap, MapFlags, ProtFlags},
};

fn posix_result(ret: i32) -> PosixResult<u32> {
	match ret {
		x if x < 0 => Err(Errno::from_raw_os_error(-x)),
		x => Ok(x as u32),
	}
}

struct Queue<T: 'static + Debug> {
	our_ptr: &'static mut u32,
	their_ptr: &'static mut u32,
	flags: &'static mut u32,
	array: &'static mut [T],
}

impl<T: Debug> Debug for Queue<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Queue")
			.field("our_ptr", self.our_ptr)
			.field("their_ptr", self.their_ptr)
			.field("flags", self.flags)
			.field("array addr", &self.array.as_ptr())
			.field("array len", &self.array.len())
			.finish()
	}
}

impl<T: Default + Debug> Queue<T> {
	fn mask(&self) -> u32 {
		self.len() - 1
	}

	fn len(&self) -> u32 {
		self.array.len() as u32
	}

	fn get_empty_nth(&mut self, seek: i32) -> Option<&mut T> {
		let effective_our = (*self.our_ptr as i32).wrapping_add(seek) as u32;
		let their = *self.their_ptr;

		// Queue is full.
		if effective_our.wrapping_sub(their) & self.mask() == 0 && effective_our != their {
			None
		} else {
			Some(unsafe {
				self.array
					.get_unchecked_mut((effective_our & self.mask()) as usize)
			})
		}
	}

	fn push(&mut self, item: &mut T) -> Result<(), ()> {
		match self.get_empty_nth(0) {
			Some(slot) => {
				*slot = core::mem::take(item);
				*self.our_ptr += 1;
				Ok(())
			}
			None => Err(()),
		}
	}

	fn pop(&mut self) -> Option<T> {
		if *self.our_ptr == *self.their_ptr {
			return None;
		}

		let item = unsafe {
			self.array
				.get_unchecked((*self.our_ptr).rem(self.array.len() as u32) as usize)
		};
		// Effectively a `.take()`, but since we're never looking at that slot again there's no need to clear it.
		let result = unsafe { ptr::read(item) };

		*self.our_ptr += 1;

		Some(result)
	}
}

#[derive(Debug)]
struct SubmissionData {
	waker: Waker,
	cqe: Option<Cqe>,
}

#[derive(Debug)]
pub struct Uring {
	fd: OwnedFd,
	sq: Queue<Sqe>,
	cq: Queue<io_uring_cqe>,
	queue_map_len: u32,
	queue_base: NonNull<u32>,
	sq_entries: NonNull<Sqe>,
	submissions: HashMap<u64, SubmissionData>,
	in_flight: u32,
	ticket: u64,
}

impl Uring {
	const NR_SQ_ENTRIES: u32 = 4096;

	pub fn new() -> PosixResult<Self> {
		let mut params = io_uring_params {
			sq_entries: Uring::NR_SQ_ENTRIES,
			cq_entries: Uring::NR_SQ_ENTRIES,
			flags: IoringSetupFlags::SUBMIT_ALL
				| IoringSetupFlags::COOP_TASKRUN
				| IoringSetupFlags::SINGLE_ISSUER
				| IoringSetupFlags::DEFER_TASKRUN,
			sq_thread_cpu: 0,
			sq_thread_idle: 0,
			features: IoringFeatureFlags::empty(),
			wq_fd: 0,
			resv: [0; 3],
			sq_off: Default::default(),
			cq_off: Default::default(),
		};

		let fd = io_uring_setup(Uring::NR_SQ_ENTRIES, &mut params)?;

		// Make sure this kernel supports all the features we assume.
		if !params.features.contains(
			IoringFeatureFlags::SINGLE_MMAP
				| IoringFeatureFlags::NODROP
				| IoringFeatureFlags::SUBMIT_STABLE,
		) {
			return Err(rustix::io::Errno::NOSYS);
		}

		unsafe {
			let queue_map_len =
				params.sq_off.array as usize + params.sq_entries as usize * size_of::<u32>();
			let queues_ptr = mmap(
				ptr::null_mut(),
				queue_map_len,
				ProtFlags::READ | ProtFlags::WRITE,
				MapFlags::SHARED | MapFlags::POPULATE,
				&fd,
				IORING_OFF_SQ_RING,
			)?;
			let sq_entries_ptr = mmap(
				ptr::null_mut(),
				params.sq_entries as usize * size_of::<io_uring_sqe>(),
				ProtFlags::READ | ProtFlags::WRITE,
				MapFlags::SHARED | MapFlags::POPULATE,
				&fd,
				IORING_OFF_SQES,
			)?;

			// Map sq array position `i` to index `i` in entries array so we can just forget about it.
			let sq_array: *mut u32 = queues_ptr.byte_offset(params.sq_off.array as isize).cast();
			for i in 0..params.sq_entries {
				*sq_array.offset(i as isize) = i;
			}

			#[inline]
			unsafe fn to_ptr(base: *mut c_void, offset: u32) -> &'static mut u32 {
				&mut *base.byte_offset(offset as isize).cast()
			}

			let sq: Queue<Sqe> = Queue {
				our_ptr: to_ptr(queues_ptr, params.sq_off.tail),
				their_ptr: to_ptr(queues_ptr, params.sq_off.head),
				flags: to_ptr(queues_ptr, params.sq_off.flags),
				array: core::slice::from_raw_parts_mut(
					sq_entries_ptr.cast(),
					params.sq_entries as usize,
				),
			};

			let cq: Queue<io_uring_cqe> = Queue {
				our_ptr: to_ptr(queues_ptr, params.cq_off.head),
				their_ptr: to_ptr(queues_ptr, params.cq_off.tail),
				flags: to_ptr(queues_ptr, params.cq_off.flags),
				array: core::slice::from_raw_parts_mut(
					queues_ptr.byte_offset(params.cq_off.cqes as isize).cast(),
					params.cq_entries as usize,
				),
			};

			Ok(Self {
				fd,
				sq,
				cq,
				sq_entries: NonNull::new_unchecked(sq_entries_ptr.cast()),
				queue_base: NonNull::new_unchecked(queues_ptr.cast()),
				queue_map_len: queue_map_len as u32,
				submissions: HashMap::new(),
				in_flight: 0,
				ticket: 0,
			})
		}
	}

	pub fn push(&mut self, mut sqe: Sqe) -> Option<()> {
		assert!(self
			.submissions
			.insert(
				sqe.user_data.u64_(),
				SubmissionData {
					waker: Waker::noop().clone(),
					cqe: None
				}
			)
			.is_none());

		loop {
			let x = self.sq.push(&mut sqe);

			if x.is_ok() {
				return Some(());
			}

			self.submit(0)?;
		}
	}

	pub fn submit(&mut self, min_completions: u32) -> Option<u32> {
		let to_submit = *self.sq.our_ptr - *self.sq.their_ptr;
		self.in_flight += to_submit;

		if min_completions > self.in_flight {
			return None;
		}

		let submitted = loop {
			match unsafe {
				io_uring_enter(
					&self.fd,
					to_submit,
					min_completions,
					IoringEnterFlags::GETEVENTS,
					ptr::null(),
					0,
				)
			} {
				Ok(x) => break x,
				Err(Errno::AGAIN | Errno::INTR) => continue,
				x => x.expect("io_uring_enter failed"),
			};
		};

		while let Some(cqe) = self.cq.pop() {
			self.in_flight -= 1;

			let ticket = cqe.user_data.u64_();
			// Normally this should always be found, if not early return to tell the caller they fucked up.
			let submission = self
				.submissions
				.get_mut(&ticket)
				.expect("request associated with cqe not found");
			submission.cqe = Some(Cqe(cqe));
			submission.waker.wake_by_ref();
		}

		Some(submitted)
	}

	pub fn sq_enqueued(&self) -> u16 {
		(*self.sq.our_ptr - *self.sq.their_ptr).try_into().unwrap()
	}

	pub fn cq_enqueued(&self) -> u16 {
		(*self.cq.their_ptr - *self.cq.our_ptr).try_into().unwrap()
	}

	pub fn in_flight(&self) -> u32 {
		self.in_flight
	}

	pub fn map_entries(&self) -> usize {
		self.submissions.len()
	}

	pub fn get_ticket(&mut self) -> NonZeroU64 {
		// At 10 billion additions per second, this would take 58 years to overflow.
		self.ticket += 1;
		NonZeroU64::new(self.ticket).unwrap()
	}

	pub fn poll(&mut self, user_data: u64, context: Option<&Context>) -> Option<Cqe> {
		let waker = context.map(|x| x.waker()).unwrap_or(Waker::noop());

		match self.submissions.get_mut(&user_data) {
			None => panic!("request associated with user_data not found"),
			Some(data) => {
				// Subsequent poll.
				if data.cqe.is_some() {
					// We have data for you!
					let cqe = data.cqe.take();
					self.submissions.remove(&user_data);

					cqe
				} else {
					// No data yet :(
					if !data.waker.will_wake(waker) {
						data.waker.clone_from(waker);
					}

					None
				}
			}
		}
	}
}

impl Drop for Uring {
	fn drop(&mut self) {
		unsafe {
			let nr_sq_entries = self.sq.len() as usize;

			munmap(self.queue_base.as_ptr().cast(), self.queue_map_len as usize).unwrap();

			munmap(
				self.sq_entries.as_ptr().cast(),
				nr_sq_entries * size_of::<io_uring_sqe>(),
			)
			.unwrap();
		}
	}
}

#[derive(Default)]
#[repr(transparent)]
pub struct Sqe(io_uring_sqe);

impl Sqe {
	/// # Safety
	/// These will be passed nearly unmodified to the io_uring subsystem.
	/// These are effectively syscalls, follow the relevant safety info in the docs.
	pub unsafe fn new(sqe: io_uring_sqe) -> Self {
		Sqe(sqe)
	}

	pub fn set_user_data(mut self, user_data: u64) -> Self {
		self.user_data = io_uring_user_data::from_u64(user_data);
		self
	}
}

impl Debug for Sqe {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Sqe")
			.field("user_data", &self.user_data.ptr())
			.finish()
	}
}

impl Deref for Sqe {
	type Target = io_uring_sqe;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl DerefMut for Sqe {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.0
	}
}

#[repr(transparent)]
#[derive(Debug, Default)]
pub struct Cqe(io_uring_cqe);

impl Deref for Cqe {
	type Target = io_uring_cqe;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl DerefMut for Cqe {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.0
	}
}

pub fn block_on<F: Future>(ring: &RefCell<Uring>, mut fut: F) -> F::Output {
	loop {
		if let Poll::Ready(x) = Future::poll(
			unsafe { Pin::new_unchecked(&mut fut) },
			&mut Context::from_waker(Waker::noop()),
		) {
			break x;
		}

		let mut borrowed_ring = ring.borrow_mut();
		if borrowed_ring.sq_enqueued() != 0 || borrowed_ring.in_flight != 0 {
			borrowed_ring.submit(1);
		}
	}
}

#[derive(Clone, Copy, Debug)]
pub struct IPromsieNotToMemForget;

impl IPromsieNotToMemForget {
	/// # Safety
	/// Types that use this require you don't `mem::forget` them.
	/// Leaking and dropping are fine, but `mem::forget` would let you reuse buffers the OS has a reference to.
	/// Normal people don't `mem::forget` anyway, but it's technically legal so here's the one unsafe block you need to write to say you won't do that to me.
	pub unsafe fn new() -> Self {
		Self
	}
}

#[cfg(test)]
mod test {
	use core::cell::RefCell;

	use super::*;
	use crate::ops::UringOp;

	#[test]
	fn new_ring() {
		let _ = Uring::new().unwrap();
	}

	#[test]
	fn one_nop() {
		let ring = RefCell::new(Uring::new().unwrap());
		let pinky_promise = unsafe { IPromsieNotToMemForget::new() };

		block_on(&ring, async {
			ops::Nop::new(&ring).build(pinky_promise).await;
		});
	}

	#[test]
	fn many_nop() {
		let ring = RefCell::new(Uring::new().unwrap());
		let pinky_promise = unsafe { IPromsieNotToMemForget::new() };

		block_on(&ring, async {
			let mut arr = vec![];

			for _ in 0..4096 {
				arr.push(ops::Nop::new(&ring).build(pinky_promise));
			}
			for nop in arr {
				nop.await;
			}
		})
	}
}
