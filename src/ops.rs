use core::{
	marker::PhantomPinned,
	mem,
	pin::Pin,
	ptr::NonNull,
	task::{Context, Poll, Waker},
};

use rustix::io_uring::{IoringCqeFlags, io_uring_cqe, io_uring_sqe};

use crate::{CompletionCallback, Sqe, Uring};

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

#[derive(Debug, Default)]
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
		Self::default()
	}

	pub fn init(self: Pin<&mut Self>, ring: &mut Uring, sqe: io_uring_sqe) {
		unsafe {
			let this = Pin::into_inner_unchecked(self);
			this.callback = Some(Self::op_completion_callback);
			ring.push(Sqe::new(
				sqe,
				NonNull::new_unchecked(&raw mut this.callback),
			))
			.unwrap();
		}
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
