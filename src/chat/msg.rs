use serde::{
    Serialize,
    Deserialize,
};


#[derive(Serialize, Deserialize, Debug)]
pub enum MsgType{
    ErrorCode,
    PeerMessage,
    ServerMessage,
    InitialMessage,
    PublicKeyRequest,
    PublicKeyResponse,
    SecurityChallenge,
    SecurityResponse,
    SymKeyExchange,
}

#[derive(Serialize, Deserialize)]
pub struct SymEncryptedMsg{
    pub msg: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ServerMessage{
    pub kind: MsgType,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ServerMessage{
    pub fn new(data: Vec<u8>, signature: Vec<u8>) -> Self{
        ServerMessage { 
            kind: MsgType::ServerMessage,
            data,
            signature,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PeerMessage{
    pub kind: MsgType,
    pub user: String,
    pub machine: String,
    pub en_msg: SymEncryptedMsg,
}

impl PeerMessage{
    pub fn new(user: String, machine: String, en_msg: SymEncryptedMsg) -> Self{
        PeerMessage { 
            kind: MsgType::PeerMessage,
            user, 
            machine, 
            en_msg, 
        }
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct InitialMessage{
    pub kind: MsgType,
    pub username: String,
    pub machine: String,
}

impl InitialMessage{
    pub fn new(username: String, machine: String) -> Self{
        InitialMessage { 
            kind: MsgType::InitialMessage, 
            username,
            machine,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyRequest {
    pub kind: MsgType,
}

impl PublicKeyRequest{
    pub fn new() -> Self{
        PublicKeyRequest { kind: MsgType::PublicKeyRequest }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SymKeyExchange {
    pub kind: MsgType,
    pub sym_key: Vec<u8>,
}

impl SymKeyExchange{
    pub fn new(sym_key: Vec<u8>) -> SymKeyExchange{
        SymKeyExchange { 
            kind: MsgType::SymKeyExchange, 
            sym_key: sym_key, 
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub kind: MsgType,
    pub pub_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct SecurityChallenge {
    pub kind: MsgType,
    pub challenge_text: Vec<u8>,
}

impl SecurityChallenge{
    pub fn new(challenge_text: Vec<u8>) -> SecurityChallenge{
        SecurityChallenge{
            kind: MsgType::SecurityChallenge,
            challenge_text,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SecurityResponse {
    pub kind: MsgType,
    pub challenge_text: String,
    pub signature: Vec<u8>
}

impl SecurityResponse{
    pub fn new(challenge_text: String, signature: Vec<u8>) -> SecurityResponse{
        SecurityResponse{
            kind: MsgType::SecurityResponse,
            challenge_text,
            signature,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorCode{
    kind: MsgType,
    pub error_number: i32,
    pub plain_text: String,
}

impl ErrorCode{
    pub fn new(error_number: i32, plain_text: String) -> Self{
        ErrorCode { 
            kind: MsgType::ErrorCode,
            error_number, 
            plain_text, 
        }
    }
}