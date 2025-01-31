use core::{
	cell::RefCell,
	future::Future,
	marker::PhantomPinned,
	mem,
	pin::Pin,
	task::{Context, Poll, Waker},
};

use crate::*;

#[derive(Debug, Default)]
pub struct Op(PendingCqe);

impl Op {
	pub fn new() -> Self {
		Self::default()
	}

	/// # Safety
	/// `Sqe` will be passed almost directly to io_uring, and the low-level unsafe power it weilds.
	pub unsafe fn activate(self: Pin<&mut Self>, ring: &mut Uring, mut sqe: Sqe) {
		let this = &mut unsafe { Pin::into_inner_unchecked(self) }.0;
		*this = PendingCqe::Pending(Waker::noop().clone(), PhantomPinned);

		sqe.user_data.ptr = io_uring_ptr {
			ptr: (&raw mut *this).cast(),
		};
		ring.push(sqe);
	}
}

impl Future for Op {
	type Output = Cqe;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = &mut unsafe { Pin::into_inner_unchecked(self) }.0;
		match this {
			PendingCqe::Pending(waker, _) => {
				waker.clone_from(cx.waker());
				Poll::Pending
			}
			PendingCqe::Complete(cqe) => Poll::Ready(cqe.clone()),
		}
	}
}

#[derive(Debug)]
enum OpWrapper<'a, T: Debug> {
	Before((&'a RefCell<Uring>, T)),
	After(Op),
}

impl<'a, T: Debug> OpWrapper<'a, T> {
	fn new(ring: &'a RefCell<Uring>, before: T) -> Self {
		Self::Before((ring, before))
	}

	fn poll(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		sqe_factory: impl FnOnce(T) -> Sqe,
	) -> Poll<Cqe> {
		let this = unsafe { Pin::into_inner_unchecked(self) };
		match this {
			Self::Before(_) => {
				// This lets us take ownership of the current `this`, while also replacing it with the new version it'll need.
				let (ring, before) = match mem::replace(this, OpWrapper::After(Op::default())) {
					Self::Before((ring, before)) => (ring, before),
					_ => unreachable!(),
				};

				let sqe = sqe_factory(before);

				match this {
					Self::After(op) => {
						unsafe {
							Pin::new_unchecked(op).activate(ring.borrow_mut().deref_mut(), sqe)
						};
					}
					_ => unreachable!(),
				}

				Poll::Pending
			}
			Self::After(op) => unsafe { Pin::new_unchecked(op) }.poll(cx),
		}
	}
}

#[derive(Debug)]
pub struct Nop<'a>(OpWrapper<'a, ()>);

impl<'a> Nop<'a> {
	pub fn new(ring: &'a RefCell<Uring>) -> Self {
		Self(OpWrapper::new(ring, ()))
	}
}

impl Future for Nop<'_> {
	type Output = ();

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let inner = unsafe { Pin::new_unchecked(&mut Pin::into_inner_unchecked(self).0) };
		inner
			.poll(cx, |_| {
				Sqe(io_uring_sqe {
					opcode: IoringOp::Nop,
					..Default::default()
				})
			})
			.map(|_| ())
	}
}

#[cfg(test)]
mod test {
	use core::cell::RefCell;

	use crate::*;

	#[test]
	fn nop() {
		let ring = RefCell::new(Uring::new().unwrap());

		let nop = ops::Nop::new(&ring);
		block_on(&ring, nop);
	}
}
