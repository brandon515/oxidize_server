use serde::{
    Serialize,
    Deserialize,
};


#[derive(Serialize, Deserialize)]
pub enum MsgType{
    ErrorCode,
    MasterMessage,
    InitialMessage,
    PublicKeyRequest,
    PublicKeyResponse,
    SecurityChallenge,
    SymKeyExchange,
}

#[derive(Serialize, Deserialize)]
pub struct SymEncryptedMsg{
    pub msg: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct MasterMessage{
    pub kind: MsgType,
    pub user: String,
    pub machine: Vec<u8>,
    pub en_msg: SymEncryptedMsg,
}

impl MasterMessage{
    pub fn new(user: String, machine: Vec<u8>, en_msg: SymEncryptedMsg) -> Self{
        MasterMessage { 
            kind: MsgType::MasterMessage,
            user, 
            machine, 
            en_msg, 
        }
    }
}


#[derive(Serialize, Deserialize)]
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
    pub sym_key: String,
}

impl SymKeyExchange{
    pub fn new(sym_key: String) -> SymKeyExchange{
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
    pub challenge_text: String,
}

impl SecurityChallenge{
    pub fn new(challenge_text: String) -> SecurityChallenge{
        SecurityChallenge{
            kind: MsgType::SecurityChallenge,
            challenge_text,
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