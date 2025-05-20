use rustix::fd::{AsFd, AsRawFd, BorrowedFd};

use crate::*;

mod private {
	pub trait Sealed {}
}

pub trait UringFd: private::Sealed {
	fn fd(&self) -> i32;
	fn is_fixed(&self) -> bool;
}

impl<T: AsFd> private::Sealed for T {}

impl<T: AsFd> UringFd for T {
	fn fd(&self) -> i32 {
		self.as_fd().as_raw_fd()
	}

	fn is_fixed(&self) -> bool {
		false
	}
}

#[derive(Debug)]
pub struct FixedFd<'a> {
	pub(crate) ring: &'a RefCell<Uring>,
	pub(crate) fd: i32,
}

impl Drop for FixedFd<'_> {
	fn drop(&mut self) {
		unsafe {
			self.ring
				.borrow_mut()
				.return_fixed_file(self.fd.try_into().unwrap());
		}
	}
}

impl private::Sealed for FixedFd<'_> {}

impl UringFd for FixedFd<'_> {
	fn fd(&self) -> i32 {
		self.fd
	}

	fn is_fixed(&self) -> bool {
		true
	}
}

#[derive(Debug)]
pub(crate) struct FixedFileSet {
	size: u32,
	bitset: Box<[usize]>,
}

impl FixedFileSet {
	pub(crate) unsafe fn new(ring_fd: BorrowedFd, size: u32) -> Result<Self, Errno> {
		if size > i32::MAX as u32 {
			return Err(Errno::DOM);
		} else if size != 0 {
			let mut arg: io_uring_rsrc_register = unsafe { MaybeUninit::zeroed().assume_init() };
			arg.nr = size;
			arg.flags = IoringRsrcFlags::REGISTER_SPARSE;

			unsafe {
				io_uring_register(
					ring_fd,
					IoringRegisterOp::RegisterFiles2,
					(&raw const arg).cast(),
					mem::size_of::<io_uring_rsrc_register>() as u32,
				)
			}?;
		}

		Ok(Self {
			size,
			bitset: vec![
				0usize;
				(size as usize).next_multiple_of(mem::size_of::<usize>())
					/ mem::size_of::<usize>()
			]
			.into(),
		})
	}

	pub(crate) fn alloc(&mut self) -> Option<u32> {
		let mut idx = 0;
		for word in self.bitset.iter_mut() {
			let within_idx = word.leading_ones();
			idx += within_idx;

			if within_idx != usize::BITS && idx < self.size {
				// pos_within
				// -----v
				// 111110..0
				//      ^--- amount to shift
				// LLVM seems to simplify this with BMI anyway.
				*word ^= 1usize << (usize::BITS - within_idx - 1);
				return Some(idx);
			}
		}

		None
	}

	pub(crate) fn dealloc(&mut self, idx: u32) {
		let word_idx = idx / usize::BITS;
		let within_idx = idx % usize::BITS;

		let word = &mut self.bitset[word_idx as usize];
		let prev = *word;
		*word ^= 1 << (usize::BITS - within_idx - 1);

		// Make sure we just set it to a 0
		assert!(prev > *word);
	}
}

#[cfg(test)]
mod test {
	use crate::fd::*;

	#[test]
	fn fixed_file_sanity() {
		let ring = RefCell::new(Uring::new(64, 2).unwrap());
		dbg!(&ring.borrow().fixed_files);
		let f1 = Uring::get_fixed_file(&ring).unwrap();
		let f2 = Uring::get_fixed_file(&ring).unwrap();
		assert!(Uring::get_fixed_file(&ring).is_none());
		assert_ne!(f1.fd, f2.fd);
	}
}
