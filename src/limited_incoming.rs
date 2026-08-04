/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * Accept-side TCP connection limiter for tonic gRPC.
 */

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::Future;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::transport::server::Connected;

/// TCP stream that holds a semaphore permit until dropped (connection closed).
pub struct CountedTcpStream {
    inner: TcpStream,
    _permit: OwnedSemaphorePermit,
}

impl Connected for CountedTcpStream {
    type ConnectInfo = <TcpStream as Connected>::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.inner.connect_info()
    }
}

impl AsyncRead for CountedTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CountedTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

type PermitFut = Pin<Box<dyn Future<Output = OwnedSemaphorePermit> + Send>>;

enum AcceptState {
    Idle,
    WaitingPermit(PermitFut),
    WaitingAccept(OwnedSemaphorePermit),
}

/// Incoming TCP connections gated by a semaphore (max concurrent connections).
pub struct LimitedTcpIncoming {
    listener: TcpListener,
    permits: Arc<Semaphore>,
    accept_state: AcceptState,
}

impl LimitedTcpIncoming {
    pub fn new(listener: TcpListener, max_connections: usize) -> Self {
        Self {
            listener,
            permits: Arc::new(Semaphore::new(max_connections.max(1))),
            accept_state: AcceptState::Idle,
        }
    }
}

impl futures::Stream for LimitedTcpIncoming {
    type Item = Result<CountedTcpStream, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.accept_state {
                AcceptState::Idle => {
                    let permits = Arc::clone(&this.permits);
                    this.accept_state = AcceptState::WaitingPermit(Box::pin(async move {
                        permits
                            .acquire_owned()
                            .await
                            .expect("semaphore closed")
                    }));
                }
                AcceptState::WaitingPermit(_) => {
                    let AcceptState::WaitingPermit(mut fut) =
                        std::mem::replace(&mut this.accept_state, AcceptState::Idle)
                    else {
                        unreachable!()
                    };
                    match fut.as_mut().poll(cx) {
                        Poll::Ready(permit) => {
                            this.accept_state = AcceptState::WaitingAccept(permit);
                        }
                        Poll::Pending => {
                            this.accept_state = AcceptState::WaitingPermit(fut);
                            return Poll::Pending;
                        }
                    }
                }
                AcceptState::WaitingAccept(_) => {
                    match this.listener.poll_accept(cx) {
                        Poll::Ready(Ok((stream, _))) => {
                            let AcceptState::WaitingAccept(permit) =
                                std::mem::replace(&mut this.accept_state, AcceptState::Idle)
                            else {
                                unreachable!()
                            };
                            return Poll::Ready(Some(Ok(CountedTcpStream {
                                inner: stream,
                                _permit: permit,
                            })));
                        }
                        Poll::Ready(Err(e)) => {
                            this.accept_state = AcceptState::Idle;
                            return Poll::Ready(Some(Err(e)));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}
