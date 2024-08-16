use core::{
	cell::RefCell,
	pin::Pin,
	task::{Context, Poll, Waker},
};
use std::collections::VecDeque;

use futures::Future;

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

#[must_use]
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

#[cfg(test)]
mod test {
	use core::future::join;

	use super::*;

	#[test]
	fn semaphore() {
		let semaphore = Semaphore::new(1);
		let resource = RefCell::new(vec![]);

		struct Delay(bool);

		impl Future for Delay {
			type Output = ();

			fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
				let this = Pin::into_inner(self);
				if this.0 {
					return Poll::Ready(());
				}

				this.0 = true;
				cx.waker().wake_by_ref();
				Poll::Pending
			}
		}

		async fn foo(semaphore: &Semaphore, resource: &RefCell<Vec<&'static str>>) {
			let _guard = semaphore.wait().await;
			{
				resource.borrow_mut().push("start");
			}
			// Nop
			Delay(false).await;
			{
				resource.borrow_mut().push("end");
			}
		}

		futures::executor::block_on(join!(
			foo(&semaphore, &resource),
			foo(&semaphore, &resource)
		));

		assert_eq!(resource.into_inner(), ["start", "end", "start", "end"]);
	}
}
