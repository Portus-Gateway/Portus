//! Feed connections the listener manager accepted into a Rama service, the
//! way Rama's own `TcpListener::serve` would: on the original socket, with
//! `SocketInfo` (real peer address and listener port) on the stream.

use log::{debug, info};
use rama::extensions::ExtensionsRef;
use rama::graceful::ShutdownGuard;
use rama::net::stream::SocketInfo;
use rama::rt::Executor;
use rama::tcp::TcpStream;
use rama::Service;

/// Accept handed-off connections until the shutdown guard is cancelled:
/// new connections stop being taken, the ones in flight finish under the
/// executor's guard.
pub async fn handoff_loop<S>(mut rx: tokio::sync::mpsc::Receiver<std::net::TcpStream>, service: S, exec: Executor, guard: ShutdownGuard)
where
    S: Service<TcpStream> + Clone,
{
    loop {
        let std_stream = tokio::select! {
            next = rx.recv() => match next {
                Some(s) => s,
                None => break,
            },
            () = guard.cancelled() => {
                info!("rama: shutdown signalled, no longer accepting connections");
                break;
            }
        };
        let stream = match tokio::net::TcpStream::from_std(std_stream) {
            Ok(s) => s,
            Err(e) => {
                debug!("rama: handed-off socket could not join the runtime: {e}");
                continue;
            }
        };
        let peer = match stream.peer_addr() {
            Ok(p) => p,
            Err(e) => {
                debug!("rama: handed-off socket has no peer address: {e}");
                continue;
            }
        };
        let local = stream.local_addr().ok();
        // Rama sets no socket options; Pingora sets TCP_NODELAY on every accepted
        // and dialled socket. Without it, a response whose header and body are
        // written separately (bodies above hyper's coalescing threshold) stalls
        // on Nagle + delayed ACK: the 16 KB rungs measured p99 47 ms.
        if let Err(e) = stream.set_nodelay(true) {
            debug!("rama: TCP_NODELAY on handed-off socket: {e}");
        }
        let stream = TcpStream::new(stream);
        stream.extensions().insert(SocketInfo::new(local.map(Into::into), peer.into()));
        let service = service.clone();
        exec.spawn_task(async move {
            let _ = service.serve(stream).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::graceful::Shutdown;
    use rama::http::server::HttpServer;
    use rama::http::{Request, Response};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Answers every request with `200` after `delay`, on a server whose
    /// executor carries the shutdown guard, as `run` builds it.
    fn slow_ok(exec: Executor, delay: Duration) -> impl Service<TcpStream> + Clone {
        HttpServer::auto(exec).service(rama::service::service_fn(move |_req: Request| async move {
            tokio::time::sleep(delay).await;
            Ok::<_, std::convert::Infallible>(Response::new(rama::http::Body::from("ok")))
        }))
    }

    /// A client connection handed to `handoff_loop`, with the client end
    /// returned for the test to drive.
    async fn connected(tx: &tokio::sync::mpsc::Sender<std::net::TcpStream>) -> tokio::net::TcpStream {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        tx.send(server.into_std().expect("std")).await.expect("handoff");
        client
    }

    async fn read_response(client: &mut tokio::net::TcpStream) -> String {
        let mut buf = vec![0u8; 4096];
        let mut out = String::new();
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf)).await.expect("response in time").expect("read");
            out.push_str(&String::from_utf8_lossy(&buf[..n]));
            if n == 0 || out.ends_with("ok") {
                return out;
            }
        }
    }

    #[tokio::test]
    async fn an_idle_keep_alive_connection_does_not_hold_up_the_drain() {
        let (fire, signal) = tokio::sync::oneshot::channel::<()>();
        let shutdown = Shutdown::new(async move { let _ = signal.await; });
        let exec = Executor::graceful(shutdown.guard());
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        exec.spawn_task(handoff_loop(rx, slow_ok(exec.clone(), Duration::ZERO), exec.clone(), shutdown.guard()));

        let mut client = connected(&tx).await;
        client.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n").await.expect("write");
        assert!(read_response(&mut client).await.starts_with("HTTP/1.1 200"));
        // The connection stays open and idle; shutdown must not wait for it.
        // The executor carries a guard of its own, so the scope that awaits the
        // drain must not hold one.
        drop(exec);
        fire.send(()).expect("signal");
        let drained = shutdown.shutdown_with_limit(Duration::from_secs(3)).await;
        assert!(drained.is_ok(), "idle keep-alive connection held the drain: {drained:?}");
    }

    #[tokio::test]
    async fn a_request_in_flight_finishes_before_the_drain_completes() {
        let (fire, signal) = tokio::sync::oneshot::channel::<()>();
        let shutdown = Shutdown::new(async move { let _ = signal.await; });
        let exec = Executor::graceful(shutdown.guard());
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        exec.spawn_task(handoff_loop(rx, slow_ok(exec.clone(), Duration::from_millis(700)), exec.clone(), shutdown.guard()));

        let mut client = connected(&tx).await;
        client.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n").await.expect("write");
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(exec);
        fire.send(()).expect("signal");
        let started = std::time::Instant::now();
        let drained = shutdown.shutdown_with_limit(Duration::from_secs(5)).await;
        assert!(drained.is_ok(), "drain timed out with one request in flight: {drained:?}");
        assert!(started.elapsed() >= Duration::from_millis(500), "drain finished before the in-flight request did");
        assert!(read_response(&mut client).await.starts_with("HTTP/1.1 200"));
    }
}
