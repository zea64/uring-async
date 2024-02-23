use core::{
	cell::RefCell,
	future::Future,
	mem::MaybeUninit,
	num::NonZeroU64,
	pin::Pin,
	task::{Context, Poll},
};

use crate::*;

pub struct Op<'a> {
	ring: &'a RefCell<Uring>,
	ticket: Option<NonZeroU64>,
}

impl<'a> Op<'a> {
	pub fn new(ring: &'a RefCell<Uring>) -> Self {
		Op {
			ring,
			ticket: None,
		}
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
					ring.submit().unwrap();
					cx.waker().wake_by_ref();
					Poll::Pending
				}
			};
		}

		let ticket = ring.get_ticket();
		self.ticket = Some(ticket);

		ring.push(sqe_factory().set_user_data(ticket.into())).unwrap();

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
		match Pin::into_inner(self).op.poll(cx, || unsafe{Sqe::new(MaybeUninit::zeroed().assume_init())}) {
			Poll::Ready(_) => Poll::Ready(()),
			Poll::Pending => Poll::Pending,
		}
	}
}

impl<'a> Nop<'a> {
	pub fn new(ring: &'a RefCell<Uring>) -> Self {
		Nop {
			op: Op::new(ring),
		}
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
