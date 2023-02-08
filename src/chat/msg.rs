use serde::{
    Serialize,
    Deserialize,
};

use crate::crypto::SymEncryptedMsg;

#[derive(Serialize, Deserialize)]
pub struct MasterMessage{
    pub user: String,
    pub machine: Vec<u8>,
    pub en_msg: SymEncryptedMsg,
}

impl MasterMessage{
    pub fn new(user: String, machine: Vec<u8>, en_msg: SymEncryptedMsg) -> Self{
        MasterMessage { 
            user, 
            machine, 
            en_msg, 
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum MsgType{
    InitialMessage,
    PublicKeyRequest,
}

#[derive(Serialize, Deserialize)]
pub struct InitialMessage{
    kind: MsgType,
    username: String,
    machine: String,
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
    kind: MsgType,
}

impl PublicKeyRequest{
    pub fn new() -> Self{
        PublicKeyRequest { kind: MsgType::PublicKeyRequest }
    }
}