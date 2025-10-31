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
    Hello { pubkey: Vec<u8>, salt: [u8; 32] },
    HelloAck { pubkey: Vec<u8>, salt: [u8; 32] },
    // Encrypted under derived key using seq=0, first nonce:
    Confirm { ct: Vec<u8> },
    // Encrypted frames (seq >= 1)
    Frame { seq: u64, ts_ns: u64, ct: Vec<u8> },
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

#[tokio::main]
async fn main() -> io::Result<()> {
    log_arm_ce();

    // tiny CLI: --mode sender|receiver --host <ip> --port <p>
    let args: Vec<String> = env::args().collect();
    let mode = args
        .iter()
        .position(|a| a == "--mode")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("receiver");
    let host = args
        .iter()
        .position(|a| a == "--host")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("127.0.0.1");
    let port = args
        .iter()
        .position(|a| a == "--port")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(5000);

    match mode {
        "receiver" => receiver(port).await,
        "sender" => sender(host, port).await,
        _ => {
            eprintln!("--mode sender|receiver");
            Ok(())
        }
    }
}

async fn sender(host: &str, port: u16) -> io::Result<()> {
    use rpi_secure_stream::aead;
    use rpi_secure_stream::keying;

    let addr = format!("{host}:{port}");
    eprintln!("SENDER: connecting to {addr}");
    let mut s = TcpStream::connect(&addr).await?;

    // --- Handshake (ECDH) ---
    let (offer_s, secret_s) = keying::start_offer(); // my pubkey + salt
    write_msg(
        &mut s,
        &Msg::Hello {
            pubkey: offer_s.pubkey_sec1.clone(),
            salt: offer_s.salt,
        },
    )
    .await?;

    let msg = read_msg(&mut s).await?;
    let (peer_pub, peer_salt) = match msg {
        Msg::HelloAck { pubkey, salt } => (pubkey, salt),
        other => {
            eprintln!("unexpected {:?}", other);
            return Ok(());
        }
    };

    // derive session from both contributions (XOR salts so both sides add entropy)
    let mut salt = [0u8; 32];
    for i in 0..32 {
        salt[i] = offer_s.salt[i] ^ peer_salt[i];
    }
    let params = keying::derive_params(&secret_s, &peer_pub, &salt);

    let mut ctr = aead::NonceCtr::new(params.nonce_base);
    let aead = aead::AeadCtx::new(params.enc_key);

    // confirm: encrypt "confirm" with seq=0 + first nonce
    let confirm_ct = aead.seal(ctr.next(), 0, b"confirm");
    write_msg(&mut s, &Msg::Confirm { ct: confirm_ct }).await?;
    eprintln!("SENDER: handshake complete");

    // --- Dummy encrypted frames ---
    for seq in 1u64..=100 {
        let ts_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let pt = format!("frame-{seq:06}").into_bytes();
        let ct = aead.seal(ctr.next(), seq, &pt);
        write_msg(&mut s, &Msg::Frame { seq, ts_ns, ct }).await?;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await; // ~100 fps max
    }
    Ok(())
}

async fn receiver(port: u16) -> io::Result<()> {
    use rpi_secure_stream::aead;
    use rpi_secure_stream::keying;

    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await?;
    eprintln!("RECEIVER: listening on {addr}");
    let (mut s, peer) = listener.accept().await?;
    eprintln!("RECEIVER: connection from {peer}");

    // --- Handshake (ECDH) ---
    let msg = read_msg(&mut s).await?;
    let (peer_pub, peer_salt) = match msg {
        Msg::Hello { pubkey, salt } => (pubkey, salt),
        other => {
            eprintln!("unexpected {:?}", other);
            return Ok(());
        }
    };

    let (offer_r, secret_r) = keying::start_offer();
    write_msg(
        &mut s,
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
    let params = keying::derive_params(&secret_r, &peer_pub, &salt);

    let mut ctr = aead::NonceCtr::new(params.nonce_base);
    let aead = aead::AeadCtx::new(params.enc_key);

    // expect Confirm (seq=0)
    match read_msg(&mut s).await? {
        Msg::Confirm { ct } => {
            let pt = aead.open(ctr.next(), 0, &ct);
            if pt != b"confirm" {
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

    // --- Receive frames ---
    loop {
        match read_msg(&mut s).await {
            Ok(Msg::Frame { seq, ts_ns, ct }) => {
                let pt = aead.open(ctr.next(), seq, &ct);
                let now_ns = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                let latency_ms = (now_ns.saturating_sub(ts_ns)) as f64 / 1e6;
                eprintln!("frame seq={seq} len={} ~{latency_ms:.2} ms", pt.len());
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
