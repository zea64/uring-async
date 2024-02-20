use core::{
	cell::RefCell,
	future::Future,
	mem::MaybeUninit,
	pin::Pin,
	task::{Context, Poll},
};

use rustix::io_uring::*;

use crate::*;

pub struct Nop<'a> {
	ring: &'a RefCell<Uring>,
	submitted: bool,
}

impl<'a> Nop<'a> {
	pub fn new(ring: &'a RefCell<Uring>) -> Self {
		Nop {
			ring,
			submitted: false,
		}
	}
}

impl<'a> Future for Nop<'a> {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = Pin::into_inner(self);
		let mut ring = match this.ring.try_borrow_mut() {
			Ok(x) => x,
			Err(_) => {
				cx.waker().wake_by_ref();
				return Poll::Pending;
			}
		};

		if this.submitted {
			return match ring.get_cqe(ptr::from_mut(this).cast()) {
				Some(_cqe) => Poll::Ready(()),
				None => {
					ring.submit().unwrap();
					cx.waker().wake_by_ref();
					Poll::Pending
				}
			};
		}

		let nop: io_uring_sqe = unsafe { MaybeUninit::zeroed().assume_init() };
		let sqe = unsafe { Sqe::new(nop, ptr::from_mut(this).cast()) };

		this.submitted = true;
		ring.push(sqe).unwrap();

		cx.waker().wake_by_ref();

		Poll::Pending
	}
}

#[cfg(test)]
mod test {
	use core::{cell::RefCell, future::join};

	use futures::executor::block_on;

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
}
