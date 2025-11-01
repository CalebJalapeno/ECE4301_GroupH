mod video;
use video::{start_sender_pipeline, ReceiverVideo};
use serde::{Deserialize, Serialize};
use std::env;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[cfg(target_arch = "aarch64")]
fn log_arm_ce() {
    eprintln!(
        "ARMv8 Crypto Extensions ? AES:{}, PMULL:{}",
        std::arch::is_aarch64_feature_detected!("aes"),
        std::arch::is_aarch64_feature_detected!("pmull")
    );
}
#[cfg(not(target_arch = "aarch64"))]
fn log_arm_ce() {
    eprintln!("ARMv8 Crypto Extensions ? N/A on this arch");
}

#[derive(Serialize, Deserialize, Debug)]
enum Msg {
    // ECDH path
    Hello { pubkey: Vec<u8>, salt: [u8; 32] },
    HelloAck { pubkey: Vec<u8>, salt: [u8; 32] },

    // RSA path
    RsaHelloReq,                // sender -> receiver
    RsaPub { pk_der: Vec<u8> }, // receiver -> sender (SPKI DER)
    RsaWrapped { ct: Vec<u8> }, // sender -> receiver (OAEP(salt||prekey))

    // Common
    Confirm { ct: Vec<u8> },                     // seq=0
    Frame { seq: u64, ts_ns: u64, ct: Vec<u8> }, // seq>=1
}

async fn write_msg(stream: &mut TcpStream, msg: &Msg) -> io::Result<()> {
    let buf = bincode::serialize(msg).unwrap();
    let len = (buf.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&buf).await
}
async fn read_msg(stream: &mut TcpStream) -> io::Result<Msg> {
    let mut lenb = [0u8; 4];
    stream.read_exact(&mut lenb).await?;
    let len = u32::from_be_bytes(lenb) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(bincode::deserialize::<Msg>(&buf).unwrap())
}

fn arg_val<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    log_arm_ce();

    // CLI: --mode sender|receiver --host <ip> --port <p> [--mech ecdh|rsa]
    let args: Vec<String> = env::args().collect();
    let mode = arg_val(&args, "--mode").unwrap_or("receiver");
    let host = arg_val(&args, "--host").unwrap_or("127.0.0.1");
    let port: u16 = arg_val(&args, "--port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);
    let mech = arg_val(&args, "--mech").unwrap_or("ecdh");

    match mode {
        "receiver" => receiver(port).await,
        "sender" => sender(host, port, mech).await,
        _ => {
            eprintln!("Usage: --mode sender|receiver [--host IP] [--port P] [--mech ecdh|rsa]");
            Ok(())
        }
    }
}

struct CryptoDirs {
    enc_tx: rpi_secure_stream::aead::AeadCtx,
    n_tx: rpi_secure_stream::aead::NonceCtr,
    enc_rx: rpi_secure_stream::aead::AeadCtx,
    n_rx: rpi_secure_stream::aead::NonceCtr,
}

async fn sender(host: &str, port: u16, mech: &str) -> io::Result<()> {
    use std::io;
    use tokio::net::TcpStream;

    let addr = format!("{host}:{port}");
    eprintln!("SENDER: connecting to {addr}");
    let mut s = TcpStream::connect(&addr).await?;

    // Handshake ? CryptoDirs
    let mut crypto = match mech {
        "rsa" => rsa_handshake_sender(&mut s).await?,
        _ => ecdh_handshake_sender(&mut s).await?,
    };

    // Confirm (seq=0)
    let ct0 = crypto.enc_tx.seal(crypto.n_tx.next(), 0, b"confirm");
    write_msg(&mut s, &Msg::Confirm { ct: ct0 }).await?;
    eprintln!("SENDER: handshake complete ({mech})");

    // ---- CAMERA ? H.264 AUs ? ENCRYPT ? SEND ----
    // Change /dev/video0 if your webcam node is different (check with: ls -l /dev/video*)
    let rx_aus = start_sender_pipeline("/dev/video0", 640, 480, 15)
        .expect("gstreamer sender");

    for (seq, au) in (1u64..).zip(rx_aus.iter()) {
        eprintln!("SENDER: AU {} bytes", au.len()); // helpful debug
        let ts_ns = now_ns();
        let ct = crypto.enc_tx.seal(crypto.n_tx.next(), seq, &au);
        write_msg(&mut s, &Msg::Frame { seq, ts_ns, ct }).await?;
    }
    Ok(())
}


async fn receiver(port: u16) -> io::Result<()> {
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await?;
    eprintln!("RECEIVER: listening on {addr}");
    let (mut s, peer) = listener.accept().await?;
    eprintln!("RECEIVER: connection from {peer}");

    // Peek first message to determine mechanism
    let first = read_msg(&mut s).await?;

    // Perform handshake ? CryptoDirs
    let mut crypto = match first {
        Msg::Hello { .. } => ecdh_handshake_receiver(&mut s, first).await?,
        Msg::RsaHelloReq => rsa_handshake_receiver(&mut s).await?,
        other => return Err(io_err(format!("unexpected first msg: {:?}", other))),
    };

    // Expect Confirm (seq=0) using RX direction
    match read_msg(&mut s).await? {
        Msg::Confirm { ct } => {
            let pt = crypto.enc_rx.open(crypto.n_rx.next(), 0, &ct);
            if pt.as_slice() != b"confirm" {
                eprintln!("bad confirm");
                return Ok(());
            }
        }
        other => {
            eprintln!("expected Confirm, got {:?}", other);
            return Ok(());
        }
    }
    eprintln!("RECEIVER: handshake complete");
	
    let video = ReceiverVideo::new().expect("gstreamer receiver");

    // Receive frames, decrypt with RX direction
    loop {
    	match read_msg(&mut s).await {
    	    Ok(Msg::Frame { seq, ts_ns, ct }) => {
    	        let au = crypto.enc_rx.open(crypto.n_rx.next(), seq, &ct);
		video.push_au(&au);
    	        let latency_ms = (now_ns().saturating_sub(ts_ns)) as f64 / 1e6;
    	        eprintln!("frame seq={seq} len={} ~{latency_ms:.2} ms", au.len());
            }
            Ok(other) => eprintln!("unexpected {:?}", other),
            Err(e) => {
                eprintln!("recv done: {e}");
                break;
            }
        }
    }
    Ok(())
}

// ---------------- Handshakes (return CryptoDirs) ----------------

async fn ecdh_handshake_sender(s: &mut TcpStream) -> io::Result<CryptoDirs> {
    use p256::PublicKey;
    use rpi_secure_stream::{aead, keying, session};

    // My offer
    let (offer_s, secret_s) = keying::start_offer();
    write_msg(
        s,
        &Msg::Hello {
            pubkey: offer_s.pubkey_sec1.clone(),
            salt: offer_s.salt,
        },
    )
    .await?;

    // Peer offer
    let (peer_pub, peer_salt) = match read_msg(s).await? {
        Msg::HelloAck { pubkey, salt } => (pubkey, salt),
        other => return Err(io_err(format!("unexpected {:?}", other))),
    };

    // Combine salts and compute ECDH shared
    let mut salt = [0u8; 32];
    for i in 0..32 {
        salt[i] = offer_s.salt[i] ^ peer_salt[i];
    }
    let peer_pk = PublicKey::from_sec1_bytes(&peer_pub).map_err(to_io)?;
    let shared = secret_s.diffie_hellman(&peer_pk);

    // Derive per-direction keys
    let sess = session::derive_bidirectional(shared.raw_secret_bytes(), &salt, b"SENDER", b"RECEIVER");
    Ok(CryptoDirs {
        enc_tx: aead::AeadCtx::new(sess.tx.enc_key),
        n_tx: aead::NonceCtr::new(sess.tx.nonce_base),
        enc_rx: aead::AeadCtx::new(sess.rx.enc_key),
        n_rx: aead::NonceCtr::new(sess.rx.nonce_base),
    })
}

async fn ecdh_handshake_receiver(
    s: &mut TcpStream,
    first: Msg,
) -> io::Result<CryptoDirs> {
    use p256::PublicKey;
    use rpi_secure_stream::{aead, keying, session};

    let (peer_pub, peer_salt) = match first {
        Msg::Hello { pubkey, salt } => (pubkey, salt),
        other => return Err(io_err(format!("expected Hello, got {:?}", other))),
    };

    let (offer_r, secret_r) = keying::start_offer();
    write_msg(
        s,
        &Msg::HelloAck {
            pubkey: offer_r.pubkey_sec1.clone(),
            salt: offer_r.salt,
        },
    )
    .await?;

    let mut salt = [0u8; 32];
    for i in 0..32 {
        salt[i] = offer_r.salt[i] ^ peer_salt[i];
    }
    let peer_pk = PublicKey::from_sec1_bytes(&peer_pub).map_err(to_io)?;
    let shared = secret_r.diffie_hellman(&peer_pk);

    let sess = session::derive_bidirectional(shared.raw_secret_bytes(), &salt, b"RECEIVER", b"SENDER");
    Ok(CryptoDirs {
        enc_tx: aead::AeadCtx::new(sess.tx.enc_key),
        n_tx: aead::NonceCtr::new(sess.tx.nonce_base),
        enc_rx: aead::AeadCtx::new(sess.rx.enc_key),
        n_rx: aead::NonceCtr::new(sess.rx.nonce_base),
    })
}

async fn rsa_handshake_sender(s: &mut TcpStream) -> io::Result<CryptoDirs> {
    use rsa::{Oaep, RsaPublicKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::rand_core::{OsRng, RngCore};
    use sha2::Sha256;
    use rpi_secure_stream::{aead, session};

    // Ask for receiver's RSA pubkey
    write_msg(s, &Msg::RsaHelloReq).await?;
    let pk_der = match read_msg(s).await? {
        Msg::RsaPub { pk_der } => pk_der,
        other => return Err(io_err(format!("expected RsaPub, got {:?}", other))),
    };
    let peer_pk = RsaPublicKey::from_public_key_der(&pk_der).map_err(to_io)?;

    // Fresh salt + prekey (prekey is the HKDF input "secret")
    let mut rng = OsRng;
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);
    let mut prekey = [0u8; 32];
    rng.fill_bytes(&mut prekey);

    // Wrap (salt||prekey) to the receiver
    let mut payload = [0u8; 64];
    payload[..32].copy_from_slice(&salt);
    payload[32..].copy_from_slice(&prekey);
    let ct = peer_pk
        .encrypt(&mut rng, Oaep::new::<Sha256>(), &payload)
        .map_err(to_io)?;
    write_msg(s, &Msg::RsaWrapped { ct }).await?;

    let sess = session::derive_bidirectional(&prekey, &salt, b"SENDER", b"RECEIVER");
    Ok(CryptoDirs {
        enc_tx: aead::AeadCtx::new(sess.tx.enc_key),
        n_tx: aead::NonceCtr::new(sess.tx.nonce_base),
        enc_rx: aead::AeadCtx::new(sess.rx.enc_key),
        n_rx: aead::NonceCtr::new(sess.rx.nonce_base),
    })
}

async fn rsa_handshake_receiver(s: &mut TcpStream) -> io::Result<CryptoDirs> {
    use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
    use rsa::pkcs8::EncodePublicKey;
    use rsa::rand_core::OsRng;
    use sha2::Sha256;
    use rpi_secure_stream::{aead, session};

    // Ephemeral RSA-2048 keypair
    let mut rng = OsRng;
    let sk = RsaPrivateKey::new(&mut rng, 2048).map_err(to_io)?;
    let pk = RsaPublicKey::from(&sk);
    let pk_der = pk.to_public_key_der().map_err(to_io)?.as_bytes().to_vec();
    write_msg(s, &Msg::RsaPub { pk_der }).await?;

    // Receive wrapped (salt||prekey)
    let ct = match read_msg(s).await? {
        Msg::RsaWrapped { ct } => ct,
        other => return Err(io_err(format!("expected RsaWrapped, got {:?}", other))),
    };
    let pt = sk.decrypt(Oaep::new::<Sha256>(), &ct).map_err(to_io)?;
    if pt.len() != 64 {
        return Err(io_err("bad RSA payload length".into()));
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&pt[..32]);
    let mut prekey = [0u8; 32];
    prekey.copy_from_slice(&pt[32..]);

    let sess = session::derive_bidirectional(&prekey, &salt, b"RECEIVER", b"SENDER");
    Ok(CryptoDirs {
        enc_tx: aead::AeadCtx::new(sess.tx.enc_key),
        n_tx: aead::NonceCtr::new(sess.tx.nonce_base),
        enc_rx: aead::AeadCtx::new(sess.rx.enc_key),
        n_rx: aead::NonceCtr::new(sess.rx.nonce_base),
    })
}

// ---------------- helpers ----------------

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}
fn io_err(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}
