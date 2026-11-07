//! Server half of the client's TCP key exchange.
//!
//! A client that registers over TCP (the "disable UDP" path) no longer sends its first message
//! itself: it waits for the server to open the connection with a signed `KeyExchange` and
//! answers with its own, carrying a stream key sealed to the server's ephemeral public key.
//! Without that opening message such a client waits out its read timeout and never registers,
//! so hbbs stays "not ready" for it.
//!
//! Peers that do not speak the exchange (plain TCP punch requests, WebSocket clients, which
//! are already encrypted by wss and skip it) are unaffected: whatever they send first is handed
//! back to the caller and the connection keeps running unencrypted, as before.

use hbb_common::{
    anyhow::anyhow,
    bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    futures_util::{
        sink::SinkExt,
        stream::{SplitSink, SplitStream, StreamExt},
    },
    log,
    protobuf::Message as _,
    rendezvous_proto::{rendezvous_message::Union, KeyExchange, KxParams, RendezvousMessage},
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::{kx_version_for, Encrypt, KxTranscript, KX_PARAMS_DOMAIN, KX_VERSION_LATEST},
    timeout,
    tokio::net::TcpStream,
    tokio_util::codec::Framed,
    ResultType,
};
use std::sync::{Arc, Mutex};

pub type TcpSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
pub type TcpSource = SplitStream<Framed<TcpStream, BytesCodec>>;
/// The stream cipher of a connection that completed the exchange, shared by its sending and
/// receiving sides so each advances its own counter on the same key.
pub type StreamCipher = Arc<Mutex<Encrypt>>;

/// Set in the last byte of the server's ephemeral public key to say it also signs `KxParams`, so
/// the client verifies that signature instead of trusting the bare key. X25519 ignores the bit.
const PK_SIGNED_PARAMS: u8 = 0x80;

/// How long a peer gets to answer the opening message before the connection is treated as one
/// that does not speak the exchange. A peer that does reply does so immediately.
const REPLY_TIMEOUT: u64 = 3_000;

pub struct KeyExchangeResult {
    /// `None` for a connection that stays in the clear.
    pub cipher: Option<StreamCipher>,
    /// The first message of a peer that answered with application data instead of a key
    /// exchange. The caller has to process it; it will not arrive again.
    pub first_message: Option<BytesMut>,
}

impl KeyExchangeResult {
    pub fn plain() -> Self {
        Self {
            cipher: None,
            first_message: None,
        }
    }
}

/// Runs the exchange on a freshly accepted connection.
pub async fn exchange(
    sink: &mut TcpSink,
    source: &mut TcpSource,
    sk: &sign::SecretKey,
) -> ResultType<KeyExchangeResult> {
    let (mut our_pk, our_sk) = box_::gen_keypair();
    our_pk.0[31] |= PK_SIGNED_PARAMS;

    let params = KxParams {
        pk: our_pk.0.to_vec().into(),
        version: KX_VERSION_LATEST,
        ..Default::default()
    };
    let mut signed = KX_PARAMS_DOMAIN.to_vec();
    signed.extend_from_slice(&params.write_to_bytes()?);

    let mut msg_out = RendezvousMessage::new();
    msg_out.set_key_exchange(KeyExchange {
        keys: vec![sign::sign(&our_pk.0, sk).into()],
        signed_params: sign::sign(&signed, sk).into(),
        version: KX_VERSION_LATEST,
        ..Default::default()
    });
    sink.send(Bytes::from(msg_out.write_to_bytes()?)).await?;

    let reply = match timeout(REPLY_TIMEOUT, source.next()).await {
        Ok(Some(Ok(bytes))) => bytes,
        // Nothing came back: an older peer that does not read the opening message, or one that
        // speaks first only after a while. Keep the connection, in the clear as before.
        _ => return Ok(KeyExchangeResult::plain()),
    };
    let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&reply) else {
        return Ok(KeyExchangeResult::plain());
    };
    let Some(Union::KeyExchange(ex)) = msg_in.union else {
        // The peer ignored the opening message and sent application data: hand it back.
        return Ok(KeyExchangeResult {
            cipher: None,
            first_message: Some(reply),
        });
    };
    if ex.keys.len() != 2 {
        bail!("key exchange reply carries {} keys, expected 2", ex.keys.len());
    }

    let their_pk = box_::PublicKey(to_32(&ex.keys[0][..])?);
    let sealed = box_::open(
        &ex.keys[1][..],
        &box_::Nonce([0u8; box_::NONCEBYTES]),
        &their_pk,
        &our_sk,
    )
    .map_err(|_| anyhow!("cannot open the sealed stream key"))?;
    let key = secretbox::Key(to_32(&sealed)?);

    // The client sends the version it picked, the highest the two sides speak; it is the same
    // `min` the client applied to what we advertised.
    let picked = kx_version_for(ex.version);
    let transcript = KxTranscript {
        initiator_pk: &ex.keys[0][..],
        responder_pk: &our_pk.0[..],
        advertised: KX_VERSION_LATEST,
        picked,
    };
    let cipher = if picked == 0 {
        Encrypt::new(key)
    } else {
        Encrypt::new_split(key, false, &transcript)?
    };
    log::debug!("key exchange done, stream secured with version {}", picked);
    Ok(KeyExchangeResult {
        cipher: Some(Arc::new(Mutex::new(cipher))),
        first_message: None,
    })
}

/// Encrypts one outgoing message. Called without an await between locking and sealing.
pub fn seal(cipher: &Option<StreamCipher>, bytes: Vec<u8>) -> Vec<u8> {
    let Some(cipher) = cipher.as_ref() else {
        return bytes;
    };
    match cipher.lock() {
        Ok(mut cipher) => cipher.enc(&bytes),
        Err(_) => {
            log::warn!("stream cipher lock poisoned, sending in the clear");
            bytes
        }
    }
}

/// Decrypts one incoming message in place.
pub fn unseal(cipher: &Option<StreamCipher>, bytes: &mut BytesMut) -> ResultType<()> {
    if let Some(cipher) = cipher.as_ref() {
        let mut cipher = cipher
            .lock()
            .map_err(|_| anyhow!("stream cipher lock poisoned"))?;
        cipher.dec(bytes)?;
    }
    Ok(())
}

fn to_32(bytes: &[u8]) -> ResultType<[u8; 32]> {
    <[u8; 32]>::try_from(bytes)
        .map_err(|_| anyhow!("expected 32 bytes, got {}", bytes.len()))
}
