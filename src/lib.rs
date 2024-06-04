#![feature(future_join)]

pub mod ops;

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
use std::collections::VecDeque;

use rustix::{
	fd::OwnedFd,
	io::Result as PosixResult,
	io_uring::*,
	mm::{mmap, munmap, MapFlags, ProtFlags},
};

#[derive(Debug, Default)]
struct EventInner {
	queue: VecDeque<(*const (), Waker)>,
	completed: Vec<*const ()>,
}

#[derive(Debug, Default)]
struct Event(RefCell<EventInner>);

impl<'a> Event {
	fn new() -> Self {
		Default::default()
	}

	fn listen(&'a self) -> EventListener<'a> {
		EventListener {
			event: self,
			submitted: false,
		}
	}

	fn notify(&self) -> bool {
		let mut this = self.0.borrow_mut();
		if let Some((ptr, waker)) = this.queue.pop_front() {
			this.completed.push(ptr);
			waker.wake_by_ref();
			true
		} else {
			false
		}
	}
}

struct EventListener<'a> {
	event: &'a Event,
	submitted: bool,
}

impl<'a> Future for EventListener<'a> {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = Pin::into_inner(self);
		let ptr = this as *mut _ as *const ();
		let mut event = this.event.0.borrow_mut();

		if !this.submitted {
			this.submitted = true;
			event
				.queue
				.push_back((this as *mut _ as *const (), cx.waker().clone()));
			Poll::Pending
		} else {
			let index = match event.completed.iter().position(|&x| x == ptr) {
				Some(x) => x,
				None => return Poll::Pending,
			};
			event.completed.swap_remove(index);
			Poll::Ready(())
		}
	}
}

#[derive(Debug)]
struct SemaphoreInner {
	used: usize,
	limit: usize,
}

#[derive(Debug)]
pub struct SemaphoreGuard<'a>(&'a Semaphore);

impl Drop for SemaphoreGuard<'_> {
	fn drop(&mut self) {
		let mut inner = self.0.inner.borrow_mut();
		inner.used = inner.used.checked_sub(1).expect("Semaphore underflow");
		self.0.event.notify();
	}
}

#[derive(Debug)]
pub struct Semaphore {
	inner: RefCell<SemaphoreInner>,
	event: Event,
}

impl<'a> Semaphore {
	pub fn new(limit: usize) -> Self {
		Semaphore {
			inner: RefCell::new(SemaphoreInner { used: 0, limit }),
			event: Event::new(),
		}
	}

	pub async fn wait(&'a self) -> SemaphoreGuard<'a> {
		loop {
			{
				let mut this = self.inner.borrow_mut();
				if this.used < this.limit {
					this.used += 1;
					return SemaphoreGuard(self);
				}
			}

			self.event.listen().await;
		}
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
pub struct Uring {
	fd: OwnedFd,
	sq: Queue<Sqe>,
	cq: Queue<io_uring_cqe>,
	queue_map_len: u32,
	queue_base: NonNull<u32>,
	sq_entries: NonNull<Sqe>,
	ready_cqes: Vec<Cqe>,
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
				ready_cqes: Vec::new(),
				ticket: 0,
			})
		}
	}

	pub fn push(&mut self, mut sqe: Sqe) -> PosixResult<()> {
		loop {
			let x = self.sq.push(&mut sqe);

			if x.is_ok() {
				return Ok(());
			}

			self.submit(0)?;
		}
	}

	pub fn submit(&mut self, min_completions: u32) -> PosixResult<u32> {
		let to_submit = *self.sq.our_ptr - *self.sq.their_ptr;

		let submitted = unsafe {
			io_uring_enter(
				&self.fd,
				to_submit,
				core::cmp::min(min_completions, to_submit),
				IoringEnterFlags::GETEVENTS,
				ptr::null(),
				0,
			)
		}?;

		while let Some(cqe) = self.cq.pop() {
			self.ready_cqes.push(Cqe(cqe));
		}

		Ok(submitted)
	}

	pub fn want_submit(&mut self) -> PosixResult<()> {
		todo!()
	}

	pub fn get_ticket(&mut self) -> NonZeroU64 {
		// At 10 billion additions per second, this would take 58 years to overflow.
		self.ticket += 1;
		NonZeroU64::new(self.ticket).unwrap()
	}

	pub fn get_cqe(&mut self, user_data: u64) -> Option<Cqe> {
		let index = self
			.ready_cqes
			.iter()
			.enumerate()
			.find(|cqe| cqe.1.user_data.u64_() == user_data)
			.map(|(index, _cqe)| index)?;
		Some(self.ready_cqes.swap_remove(index))
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

#[cfg(test)]
mod test {
	use core::{
		cell::RefCell,
		future::{self, join},
		mem::MaybeUninit,
	};

	use futures::executor::block_on;

	use crate::*;

	fn new_nop() -> Sqe {
		let mut a: io_uring_sqe = unsafe { MaybeUninit::zeroed().assume_init() };
		a.opcode = IoringOp::Nop;
		unsafe { Sqe::new(a) }
	}

	#[test]
	fn new_ring() {
		let _ = Uring::new().unwrap();
	}

	#[test]
	fn one_nop() {
		let mut ring = Uring::new().unwrap();

		ring.push(new_nop()).unwrap();
		ring.submit(0).unwrap();
	}

	#[test]
	fn many_nop() {
		let mut ring = Uring::new().unwrap();

		for _ in 0..(4096 * 2 + 2) {
			ring.push(new_nop()).unwrap();
		}
		ring.submit(0).unwrap();
	}

	#[test]
	fn semaphore() {
		let semaphore = Semaphore::new(1);
		let resource = RefCell::new(vec![]);

		async fn foo(semaphore: &Semaphore, resource: &RefCell<Vec<&'static str>>) {
			semaphore.wait().await;
			{
				resource.borrow_mut().push("start");
			}
			// Nop
			future::ready(()).await;
			{
				resource.borrow_mut().push("end");
			}
		}

		block_on(join!(
			foo(&semaphore, &resource),
			foo(&semaphore, &resource)
		));

		assert_eq!(resource.into_inner(), ["start", "end", "start", "end"]);
	}
}
