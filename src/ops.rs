use core::{
	cell::RefCell,
	marker::PhantomPinned,
	mem::{self, MaybeUninit},
	pin::Pin,
	ptr::NonNull,
	task::{Context, Poll, Waker},
};

use rustix::io_uring::*;

use crate::{CompletionCallback, Sqe, Uring};

const ZERO_SQE: io_uring_sqe = unsafe { MaybeUninit::zeroed().assume_init() };

#[derive(Debug)]
enum OpInner {
	Pending(Waker),
	Ready { res: i32, flags: IoringCqeFlags },
}

impl Default for OpInner {
	fn default() -> Self {
		Self::Pending(Waker::noop().clone())
	}
}

#[derive(Debug)]
#[must_use]
#[repr(C)]
pub struct Op {
	callback: CompletionCallback,
	inner: OpInner,
	_marker: PhantomPinned,
}

impl Op {
	unsafe fn op_completion_callback(this: *mut (), cqe: io_uring_cqe) -> bool {
		let this: &mut Op = unsafe { &mut *this.cast() };
		match mem::replace(
			&mut this.inner,
			OpInner::Ready {
				res: cqe.res,
				flags: cqe.flags,
			},
		) {
			OpInner::Pending(waker) => waker.wake(),
			OpInner::Ready { .. } => unreachable!(),
		};
		true
	}

	pub fn new() -> Self {
		Self {
			callback: Some(Self::op_completion_callback),
			inner: OpInner::Pending(Waker::noop().clone()),
			_marker: PhantomPinned,
		}
	}

	pub fn init(self: Pin<&mut Self>, ring: &mut Uring, sqe: io_uring_sqe) {
		unsafe {
			let this = Pin::into_inner_unchecked(self);
			ring.push(Sqe::new(
				sqe,
				NonNull::new_unchecked(&raw mut this.callback),
			))
			.unwrap();
		}
	}
}

impl Default for Op {
	fn default() -> Self {
		Self::new()
	}
}

impl Future for Op {
	type Output = (i32, IoringCqeFlags);

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = unsafe { Pin::into_inner_unchecked(self) };

		match this.inner {
			OpInner::Pending(..) => {
				this.inner = OpInner::Pending(cx.waker().clone());
				Poll::Pending
			}
			OpInner::Ready { res, flags } => {
				this.inner = OpInner::Pending(Waker::noop().clone());
				Poll::Ready((res, flags))
			}
		}
	}
}

pub async fn nop(ring: &RefCell<Uring>) {
	let mut sqe = ZERO_SQE;
	sqe.opcode = IoringOp::Nop;

	let mut op = Op::new();
	Op::init(
		unsafe { Pin::new_unchecked(&mut op) },
		&mut ring.borrow_mut(),
		sqe,
	);

	unsafe { Pin::new_unchecked(&mut op) }.await;
}

#[cfg(test)]
mod test {
	use core::{
		cell::RefCell,
		pin::Pin,
		task::{Context, Poll, Waker},
	};

	use crate::*;

	fn block_on<F: Future>(ring: &RefCell<Uring>, mut fut: F) -> F::Output {
		loop {
			if let Poll::Ready(x) = Future::poll(
				unsafe { Pin::new_unchecked(&mut fut) },
				&mut Context::from_waker(Waker::noop()),
			) {
				return x;
			}

			ring.borrow_mut().enter(1, None, None).unwrap();
		}
	}

	#[test]
	fn nop() {
		let ring = RefCell::new(Uring::new(1, 0).unwrap());

		let f = ops::nop(&ring);
		eprintln!("{}", core::mem::size_of_val(&f));

		block_on(&ring, f);
	}
}
