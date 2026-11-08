//! `client::Config::window_adjust_on_consume`: a channel's receive window is only replenished
//! after the application reports consumed bytes, so a channel that is not being read stops its
//! own sender without blocking the other channels of the connection.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, ChannelMsg, client};
use ssh_key::PrivateKey;
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, sleep, timeout};

const WINDOW_SIZE: u32 = 64 * 1024;
const CHUNK: usize = 16 * 1024;
/// 1 MiB in total, sixteen windows.
const CHUNKS: usize = 64;

type Received = Arc<Mutex<HashMap<ChannelId, usize>>>;

#[tokio::test]
async fn a_channel_that_is_not_read_pauses_only_itself() -> Result<(), anyhow::Error> {
    let (session, received) = connect(true).await?;

    // Channel A floods, and the application doesn't read it.
    let mut flood = session.channel_open_session().await?;
    flood.exec(false, "flood").await?;
    sleep(Duration::from_millis(300)).await;
    let stalled = received_on(&received, flood.id());
    assert!(stalled > 0, "the flood never started");
    assert!(
        stalled <= WINDOW_SIZE as usize,
        "received {stalled} bytes without consuming them, more than one window"
    );

    // Channel B on the same connection still answers.
    let mut echo = session.channel_open_session().await?;
    echo.exec(false, "echo").await?;
    let answer = timeout(Duration::from_secs(5), async {
        while let Some(msg) = echo.wait().await {
            if let ChannelMsg::Data { data } = msg {
                return data.to_vec();
            }
        }
        Vec::new()
    })
    .await?;
    assert_eq!(answer, b"pong");

    // The flood was paused, not lost: reading and reporting consumption resumes it.
    let total = timeout(Duration::from_secs(10), async {
        let mut total = 0;
        while let Some(msg) = flood.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    total += data.len();
                    flood.consumed(data.len() as u32).await.unwrap();
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        total
    })
    .await?;
    assert_eq!(total, CHUNK * CHUNKS);
    Ok(())
}

#[tokio::test]
async fn by_default_the_window_is_replenished_on_arrival() -> Result<(), anyhow::Error> {
    let (session, received) = connect(false).await?;

    let flood = session.channel_open_session().await?;
    flood.exec(false, "flood").await?;
    sleep(Duration::from_millis(300)).await;
    assert!(received_on(&received, flood.id()) > WINDOW_SIZE as usize);
    Ok(())
}

async fn connect(
    window_adjust_on_consume: bool,
) -> Result<(client::Handle<Client>, Received), anyhow::Error> {
    let addr = addr();
    tokio::spawn(run_server(addr));
    while TcpStream::connect(addr).is_err() {
        sleep(Duration::from_millis(10)).await;
    }

    let config = Arc::new(client::Config {
        window_size: WINDOW_SIZE,
        // Large enough to hold a full window of packets, so the session never blocks on it.
        channel_buffer_size: 1024,
        window_adjust_on_consume,
        ..Default::default()
    });
    let client = Client::default();
    let received = client.received.clone();
    let mut session = client::connect(config, addr, client).await?;
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let auth = session
        .authenticate_publickey("user", PrivateKeyWithHashAlg::new(key, None))
        .await?;
    assert!(auth.success(), "authentication failed");
    Ok((session, received))
}

fn received_on(received: &Received, channel: ChannelId) -> usize {
    received.lock().unwrap().get(&channel).copied().unwrap_or(0)
}

/// Find an unused local address to bind the server to.
fn addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Counts the bytes that arrive on each channel.
#[derive(Clone, Default)]
struct Client {
    received: Received,
}

impl client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        *self.received.lock().unwrap().entry(channel).or_default() += data.len();
        Ok(())
    }
}

async fn run_server(addr: SocketAddr) {
    let config = Arc::new(server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
        ..Default::default()
    });
    let mut server = Server::default();
    server.run_on_address(config, addr).await.unwrap();
}

/// `exec flood` writes `CHUNKS` chunks of `CHUNK` bytes; any other command answers `pong`.
///
/// It writes through the channel writer, which waits for the client's window. (Queueing the
/// flood with `Handle::data` instead would hold back every channel of the server session while
/// the flooded channel's window is exhausted.)
#[derive(Default)]
struct Server {
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl server::Server for Server {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        Self::default()
    }
}

impl server::Handler for Server {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(channel) = self.channels.remove(&channel) else {
            return Ok(());
        };
        let flood = data == b"flood";
        tokio::spawn(async move {
            if flood {
                let mut writer = channel.make_writer();
                for _ in 0..CHUNKS {
                    if writer.write_all(&[0u8; CHUNK]).await.is_err() {
                        return;
                    }
                }
                let _ = writer.flush().await;
            } else {
                let _ = channel.data(&b"pong"[..]).await;
            }
            let _ = channel.eof().await;
            let _ = channel.close().await;
        });
        Ok(())
    }
}
