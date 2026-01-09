/*-------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation.  All rights reserved.
 *
 * src/stream.rs
 *
 * Gateway stream abstraction supporting both TCP and Unix socket connections.
 *
 *-------------------------------------------------------------------------
 */

use std::pin::Pin;
use tokio::io::BufStream;
use tokio::net::UnixStream;
use tokio_openssl::SslStream;
use tokio::net::TcpStream;

/// Enum to support both TCP and Unix socket streams
pub enum GwStream {
    Tcp(BufStream<SslStream<TcpStream>>),
    Unix(BufStream<UnixStream>),
}

// Implement AsyncRead trait for the enum
impl tokio::io::AsyncRead for GwStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            GwStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            GwStream::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

// Implement AsyncWrite trait for the enum
impl tokio::io::AsyncWrite for GwStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            GwStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            GwStream::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            GwStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            GwStream::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            GwStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            GwStream::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl std::marker::Unpin for GwStream {}
