#![feature(pointer_byte_offsets)]

use core::{
	ffi::c_void,
	marker::PhantomData,
	mem::size_of,
	ptr::{self, NonNull},
};
use std::task::Waker;

use rustix::{
	fd::OwnedFd,
	io::Result as PosixResult,
	io_uring::*,
	mm::{mmap, munmap, MapFlags, ProtFlags},
};

struct Queue<'a, T: 'a> {
	our_ptr: &'a mut u32,
	their_ptr: &'a mut u32,
	flags: &'a mut u32,
	array: &'a mut [T],
}

impl<'a, T> core::fmt::Debug for Queue<'a, T> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("Queue")
			.field("our_ptr", self.our_ptr)
			.field("their_ptr", self.their_ptr)
			.field("flags", self.flags)
			.field("array addr", &self.array.as_ptr())
			.field("array len", &self.array.len())
			.finish()
	}
}

impl<'a, T: Default> Queue<'a, T> {
	fn mask(&self) -> u32 {
		self.len() - 1
	}

	fn len(&self) -> u32 {
		self.array.len() as u32
	}

	fn get_nth(&mut self, seek: i32) -> &mut T {
		let effective_our = (*self.our_ptr as i32).wrapping_add(seek) as u32;

		unsafe {
			self.array
				.get_unchecked_mut((effective_our & self.mask()) as usize)
		}
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
		let item = self.get_empty_nth(0)?;
		// Effectively a `.take()`, but since we're never looking at that slot again there's no need to clear it.
		let result = unsafe { ptr::read(item) };

		*self.our_ptr += 1;

		Some(result)
	}
}

pub struct Uring<'a> {
	fd: OwnedFd,
	sq: Queue<'a, io_uring_sqe>,
	cq: Queue<'a, io_uring_cqe>,
	queue_base: NonNull<u32>,
	queue_map_len: u32,
	sq_entries: NonNull<io_uring_sqe>,
	callbacks: Box<[Option<Callback>]>,
}

impl<'a> Uring<'a> {
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
			let queue_map_len = params.sq_off.array as usize + params.sq_entries as usize * size_of::<u32>();
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
			for i in 0..params.sq_entries {
				*sq_entries_ptr.cast::<u32>().offset(i as isize) = i;
			}

			#[inline]
			unsafe fn to_ptr(base: *mut c_void, offset: u32) -> &'static mut u32 {
				&mut *base.byte_offset(offset as isize).cast()
			}

			let sq: Queue<io_uring_sqe> = Queue {
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

			let mut callbacks_vec = Vec::with_capacity(Uring::NR_SQ_ENTRIES as usize);
			for _ in 0..Uring::NR_SQ_ENTRIES {
				callbacks_vec.push(None);
			}

			Ok(Self {
				fd,
				sq,
				cq,
				sq_entries: NonNull::new_unchecked(sq_entries_ptr.cast()),
				queue_base: NonNull::new_unchecked(queues_ptr.cast()),
				queue_map_len: queue_map_len as u32,
				callbacks: callbacks_vec.into_boxed_slice(),
			})
		}
	}

	pub fn push(&mut self, mut sqe: Sqe<'a>) -> PosixResult<()> {
		// Find empty slot in callback array.
		let (callback_number, callback_slot) = self
			.callbacks
			.iter_mut()
			.enumerate()
			.filter(|x| x.1.is_none())
			.nth(0)
			.unwrap();
		// Record callback.
		*callback_slot = sqe.1;
		// Link sqe/cqe to this callback.
		sqe.0.user_data.u64_ = callback_number as u64;

		loop {
			let x = self.sq.push(&mut sqe.0);

			if x.is_ok() {
				return Ok(());
			}

			self.submit()?;
		}
	}

	pub fn submit(&mut self) -> PosixResult<u32> {
		let to_submit = *self.sq.our_ptr - *self.sq.their_ptr;
		let submitted = unsafe {
			io_uring_enter(
				&self.fd,
				to_submit,
				to_submit,
				IoringEnterFlags::GETEVENTS,
				ptr::null(),
				0,
			)
		}?;

		while let Some(cqe) = self.cq.pop() {
			let callback = &mut self.callbacks[unsafe { cqe.user_data.u64_ } as usize];

			let our_cqe = Cqe(cqe);

			if let Some(mut f) = callback.take() {
				f(&our_cqe);
			}
		}

		Ok(submitted)
	}
}

impl<'a> Drop for Uring<'a> {
	fn drop(&mut self) {
		unsafe {
			let nr_sq_entries = self.sq.len() as usize;

			munmap(self.queue_base.as_ptr().cast(), self.queue_map_len as usize).unwrap();

			munmap(self.sq_entries.as_ptr().cast(), nr_sq_entries*size_of::<io_uring_sqe>()).unwrap();
		}
	}
}

type Callback = Box<dyn FnMut(&Cqe)>;

#[derive(Default)]
pub struct Sqe<'a>(io_uring_sqe, Option<Callback>, PhantomData<&'a Waker>);

impl<'a> Sqe<'a> {
	pub unsafe fn new(sqe: io_uring_sqe, callback: Callback) -> Sqe<'a> {
		Sqe(sqe, Some(callback), Default::default())
	}

	pub unsafe fn new_without_callback(sqe: io_uring_sqe) -> Sqe<'a> {
		Sqe(sqe, None, Default::default())
	}
}

#[repr(transparent)]
#[derive(Debug, Default)]
pub struct Cqe(io_uring_cqe);

#[cfg(test)]
mod test {
	use core::mem::MaybeUninit;
	use crate::*;

	fn new_nop() -> Sqe<'static> {
		let mut a: io_uring_sqe = unsafe { MaybeUninit::zeroed().assume_init() };
		a.opcode = IoringOp::Nop;
		unsafe { Sqe::new_without_callback(a) }
	}

	#[test]
	fn new_ring() {
		let _ = Uring::new().unwrap();
	}

	#[test]
	fn one_nop() {
		let mut ring = Uring::new().unwrap();

		ring.push(new_nop()).unwrap();
		ring.submit().unwrap();
	}

	#[test]
	fn many_nop() {
		let mut ring = Uring::new().unwrap();

		for _ in 0..(4096 * 2 + 2) {
			ring.push(new_nop()).unwrap();
		}
		ring.submit().unwrap();
	}

	#[test]
	fn one_callback() {
		let mut ring = Uring::new().unwrap();

		let num = 1;

		let mut nop: io_uring_sqe = unsafe { MaybeUninit::zeroed().assume_init() };
		nop.opcode = IoringOp::Nop;

		ring.push(unsafe {
			Sqe::new(
				nop,
				Box::new(move |cqe: &Cqe| println!("{:?} {}", cqe, num)),
			)
		}).unwrap();

		ring.submit().unwrap();
	}

	#[test]
	fn many_callback() {
		let mut ring = Uring::new().unwrap();

		for i in 0..(4096 * 2 + 2) {
			let mut nop: io_uring_sqe = unsafe { MaybeUninit::zeroed().assume_init() };
			nop.opcode = IoringOp::Nop;

			ring.push(unsafe {
				Sqe::new(nop, Box::new(move |cqe: &Cqe| println!("{:?} {}", cqe, i)))
			}).unwrap();

			ring.submit().unwrap();
		}
	}
}
