//! Feed connections the listener manager accepted into a Rama service, the
//! way Rama's own `TcpListener::serve` would: on the original socket, with
//! `SocketInfo` (real peer address and listener port) on the stream.

use log::debug;
use rama::extensions::ExtensionsRef;
use rama::net::stream::SocketInfo;
use rama::rt::Executor;
use rama::tcp::TcpStream;
use rama::Service;

pub async fn handoff_loop<S>(mut rx: tokio::sync::mpsc::Receiver<std::net::TcpStream>, service: S, exec: Executor)
where
    S: Service<TcpStream> + Clone,
{
    while let Some(std_stream) = rx.recv().await {
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
