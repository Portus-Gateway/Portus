// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Listeners

use std::io;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{mpsc, Mutex};

use crate::protocols::digest::{GetSocketDigest, SocketDigest};
use crate::protocols::l4::stream::Stream;

/// Receiving end of a hand-off listener: connections accepted elsewhere (for
/// example by an SNI multiplexer that decided this stream should be terminated
/// here) are delivered as `std::net::TcpStream`s. Using the std type means the
/// sender may live on a different Tokio runtime; the stream is registered with
/// this runtime's reactor when it is accepted.
///
/// `Clone` shares the underlying channel so the endpoint can be built in one
/// place and cloned into the transport stack like any other address.
#[derive(Clone)]
pub struct HandoffSource {
    rx: Arc<Mutex<mpsc::Receiver<std::net::TcpStream>>>,
}

impl HandoffSource {
    /// Wrap a channel receiver. Send already-accepted, non-blocking
    /// `std::net::TcpStream`s (`tokio::net::TcpStream::into_std`) on the sender.
    pub fn new(rx: mpsc::Receiver<std::net::TcpStream>) -> Self {
        Self {
            rx: Arc::new(Mutex::new(rx)),
        }
    }

    /// Wait for the next handed-off stream. Resolves to `None` only when every
    /// sender has been dropped.
    pub async fn recv(&self) -> Option<std::net::TcpStream> {
        self.rx.lock().await.recv().await
    }
}

impl std::fmt::Debug for HandoffSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HandoffSource")
    }
}

/// The type for generic listener for both TCP and Unix domain socket
#[derive(Debug)]
pub enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
    /// Connections handed over by another accept loop in this process.
    Handoff(HandoffSource),
}

impl From<TcpListener> for Listener {
    fn from(s: TcpListener) -> Self {
        Self::Tcp(s)
    }
}

#[cfg(unix)]
impl From<UnixListener> for Listener {
    fn from(s: UnixListener) -> Self {
        Self::Unix(s)
    }
}

#[cfg(unix)]
impl AsRawFd for Listener {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        match &self {
            Self::Tcp(l) => l.as_raw_fd(),
            Self::Unix(l) => l.as_raw_fd(),
            // A hand-off listener owns no socket; -1 is the conventional invalid
            // descriptor. The fd table used for zero-downtime upgrades skips
            // hand-off endpoints, so this value is never handed to the kernel.
            Self::Handoff(_) => -1,
        }
    }
}

#[cfg(windows)]
impl AsRawSocket for Listener {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        match &self {
            Self::Tcp(l) => l.as_raw_socket(),
            Self::Handoff(_) => std::os::windows::io::RawSocket::MAX,
        }
    }
}

impl Listener {
    /// Return the local address this listener is bound to.
    ///
    /// For TCP listeners this is the resolved address (including the
    /// OS-assigned port when the listener was bound to port 0).
    /// Returns `None` for non-TCP listeners (e.g. Unix domain sockets).
    #[cfg(test)]
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::Tcp(l) => l.local_addr().ok(),
            #[cfg(unix)]
            Self::Unix(_) => None,
            Self::Handoff(_) => None,
        }
    }

    /// Accept a connection from the listening endpoint
    pub async fn accept(&self) -> io::Result<Stream> {
        match &self {
            Self::Tcp(l) => l.accept().await.map(|(stream, peer_addr)| {
                let mut s: Stream = stream.into();
                #[cfg(unix)]
                let digest = SocketDigest::from_raw_fd(s.as_raw_fd());
                #[cfg(windows)]
                let digest = SocketDigest::from_raw_socket(s.as_raw_socket());
                digest
                    .peer_addr
                    .set(Some(peer_addr.into()))
                    .expect("newly created OnceCell must be empty");
                s.set_socket_digest(digest);
                // TODO: if listening on a specific bind address, we could save
                // an extra syscall looking up the local_addr later if we can pass
                // and init it in the socket digest here
                s
            }),
            #[cfg(unix)]
            Self::Unix(l) => l.accept().await.map(|(stream, peer_addr)| {
                let mut s: Stream = stream.into();
                let digest = SocketDigest::from_raw_fd(s.as_raw_fd());
                // note: if unnamed/abstract UDS, it will be `None`
                // (see TryFrom<tokio::net::unix::SocketAddr>)
                let addr = peer_addr.try_into().ok();
                digest
                    .peer_addr
                    .set(addr)
                    .expect("newly created OnceCell must be empty");
                s.set_socket_digest(digest);
                s
            }),
            Self::Handoff(source) => match source.recv().await {
                Some(std_stream) => {
                    let peer_addr = std_stream.peer_addr()?;
                    let stream = tokio::net::TcpStream::from_std(std_stream)?;
                    let mut s: Stream = stream.into();
                    #[cfg(unix)]
                    let digest = SocketDigest::from_raw_fd(s.as_raw_fd());
                    #[cfg(windows)]
                    let digest = SocketDigest::from_raw_socket(s.as_raw_socket());
                    digest
                        .peer_addr
                        .set(Some(peer_addr.into()))
                        .expect("newly created OnceCell must be empty");
                    s.set_socket_digest(digest);
                    Ok(s)
                }
                // Every sender is gone: nothing will ever arrive. Park instead of
                // returning an error so the service accept loop does not spin.
                None => std::future::pending().await,
            },
        }
    }
}
