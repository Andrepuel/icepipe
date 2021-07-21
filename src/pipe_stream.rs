use std::{any::Any, borrow::BorrowMut};

use crate::PinFutureLocal;

pub trait WaitThen {
    type Value;
    type Output;

    fn wait(&mut self) -> PinFutureLocal<'_, Self::Value>;
    fn then<'a>(&'a mut self, value: &'a mut Self::Value) -> PinFutureLocal<'a, Self::Output>;
}

pub trait WaitThenDyn {
    type Output;
    fn wait_dyn(&mut self) -> PinFutureLocal<'_, Box<dyn Any>>;
    fn then_dyn<'a>(&'a mut self, value: &'a mut Box<dyn Any>) -> PinFutureLocal<'_, Self::Output>;
}
impl<T: WaitThen> WaitThenDyn for T
where
    T::Value: 'static,
{
    type Output = <T as WaitThen>::Output;

    fn wait_dyn(&mut self) -> PinFutureLocal<'_, Box<dyn Any>> {
        Box::pin(async move {
            let r = self.wait().await?;
            let r: Box<dyn Any> = Box::new(r);
            Ok(r)
        })
    }

    fn then_dyn<'a>(&'a mut self, value: &'a mut Box<dyn Any>) -> PinFutureLocal<'a, Self::Output> {
        let value = value
            .downcast_mut::<<Self as WaitThen>::Value>()
            .expect("then_dyn() must always be called with the result of wait_dyn()");

        Box::pin(async move {
            let r = self.then(value).await?;

            Ok(r)
        })
    }
}

impl<T: WaitThenDyn + ?Sized> WaitThenDynExt for T {}
pub trait WaitThenDynExt: WaitThenDyn {
    fn recv(&mut self) -> PinFutureLocal<'_, Self::Output> {
        Box::pin(async move {
            let mut value = self.wait_dyn().await?;
            let output = self.then_dyn(&mut value).await?;

            Ok(output)
        })
    }
}

pub trait Control: WaitThenDyn {
    fn close(&mut self) -> PinFutureLocal<'_, ()>;
    fn rx_closed(&self) -> bool;
}

pub trait PipeStream: WaitThenDyn<Output = Option<Vec<u8>>> + Control {
    fn send<'a>(&'a mut self, data: &'a [u8]) -> PinFutureLocal<'a, ()>;
}

pub trait Consume<T>: BorrowMut<T>
where
    Self: Sized,
{
    fn consume(mut self, mut new: T) -> T {
        let old = self.borrow_mut();
        std::mem::swap(&mut new, old);
        new
    }
}
impl<T> Consume<T> for &mut T {}
