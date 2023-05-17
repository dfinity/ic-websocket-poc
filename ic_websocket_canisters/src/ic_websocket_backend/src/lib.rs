use ed25519_compact::{PublicKey, Signature};
use ic_cdk::export::candid::CandidType;
use ic_cdk_macros::*;
use serde::{Deserialize, Serialize};
use serde_cbor::from_slice;

use canister::ws_on_message;
use canister::ws_on_open;
use sock::get_cert_messages;
use sock::get_client_incoming_num;
use sock::get_client_public_key;
use sock::put_client_incoming_num;
use sock::{
    delete_client, next_client_id, put_client_caller, put_client_gateway, put_client_public_key,
    wipe,
};

pub mod canister;
pub mod sock;

// Debug method. Wipes all data in the canister.
#[update]
fn ws_wipe() {
    wipe();
}

// Messages have the following required fields (both ways).
#[derive(CandidType, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[candid_path("ic_cdk::export::candid")]
pub struct WebsocketMessage {
    pub client_id: u64,    // To or from client id.
    pub sequence_num: u64, // Both ways, messages should arrive with sequence numbers 0, 1, 2...
    pub timestamp: u64,    // Timestamp of when the message was made for the recipient to inspect.
    #[serde(with = "serde_bytes")]
    pub message: Vec<u8>, // Application message encoded in binary.
}

// One message in the list returned to the gateway polling for messages.
#[derive(CandidType, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[candid_path("ic_cdk::export::candid")]
pub struct EncodedMessage {
    client_id: u64, // The client that the gateway will forward the message to.
    key: String,    // Key for certificate verification.
    #[serde(with = "serde_bytes")]
    val: Vec<u8>, // Encoded WebsocketMessage.
}

// List of messages returned to the polling gateway.
#[derive(CandidType, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[candid_path("ic_cdk::export::candid")]
pub struct CertMessages {
    messages: Vec<EncodedMessage>, // List of messages.
    #[serde(with = "serde_bytes")]
    cert: Vec<u8>, // cert+tree constitute the certificate for all returned messages.
    #[serde(with = "serde_bytes")]
    tree: Vec<u8>, // cert+tree constitute the certificate for all returned messages.
}

// Client submits its public key and gets a new client_id back.
#[update]
fn ws_register(public_key: Vec<u8>) -> u64 {
    let client_id = next_client_id();
    let client_key = PublicKey::from_slice(&public_key).unwrap();
    // Store the client key.
    put_client_public_key(client_id, client_key);
    // The identity (caller) used in this update call will be associated with this client_id. Remember this identity.
    put_client_caller(client_id);
    client_id
}

// A method for the gateway to get the client's public key and verify the signature of the first websocket message.
#[query]
pub fn ws_get_client_key(client_id: u64) -> Vec<u8> {
    get_client_public_key(client_id).unwrap().to_vec()
}

// The first message used in ws_open().
#[derive(CandidType, Clone, Deserialize, Serialize, Eq, PartialEq, Debug)]
#[candid_path("ic_cdk::export::candid")]
struct FirstMessage {
    client_id: u64,
    canister_id: String,
}

// Open the websocket connection.
#[update]
fn ws_open(msg: Vec<u8>, sig: Vec<u8>) -> bool {
    let decoded: FirstMessage = from_slice(&msg).unwrap();

    let client_id = decoded.client_id;
    let client_key = get_client_public_key(client_id).unwrap();

    let sig = Signature::from_slice(&sig).unwrap();
    let valid = client_key.verify(&msg, &sig);

    match valid {
        Ok(_) => {
            // Remember this gateway will get the messages for this client_id.
            put_client_gateway(client_id);

            ws_on_open(client_id);
            true
        }
        Err(_) => false,
    }
}

// Close the websocket connection.
#[update]
fn ws_close(client_id: u64) {
    delete_client(client_id);
}

// Encoded message + signature from client.
#[derive(CandidType, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[candid_path("ic_cdk::export::candid")]
struct ClientMessage {
    #[serde(with = "serde_bytes")]
    val: Vec<u8>,
    #[serde(with = "serde_bytes")]
    sig: Vec<u8>,
}

// Gateway calls this method to pass on the message from the client to the canister.
#[update]
fn ws_message(msg: Vec<u8>) -> bool {
    let decoded: ClientMessage = from_slice(&msg).unwrap();
    let content: WebsocketMessage = from_slice(&decoded.val).unwrap();

    let client_id = content.client_id;

    // Verify the signature.
    let client_key = get_client_public_key(client_id).unwrap();
    let sig = Signature::from_slice(&decoded.sig).unwrap();
    let valid = client_key.verify(&decoded.val, &sig);

    match valid {
        Ok(_) => {
            // Verify the message sequence number.
            if content.sequence_num == get_client_incoming_num(client_id) {
                put_client_incoming_num(client_id, content.sequence_num + 1);
                ws_on_message(content);
                true
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

// Gateway polls this method to get messages for all the clients it serves.
#[query]
fn ws_get_messages(nonce: u64) -> CertMessages {
    get_cert_messages(nonce)
}
