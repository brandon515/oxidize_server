use tokio::{
    net::TcpStream, 
    io::{
        AsyncWriteExt,
        AsyncReadExt,
    }, sync::Mutex,
};

use crate::{
    crypto::{
        AsymKey,
        SymKey,
    },
    chat::msg::{
        ErrorCode,
        InitialMessage, PublicKeyResponse,
    }, 
    database::{Database, self},
};

use std::{
    cell::RefCell, 
    sync::Arc,
};

use rand::distributions::{
    Alphanumeric,
    DistString,
};

use self::msg::SecurityChallenge;

#[derive(Debug, PartialEq)]
pub enum Error{
    ConnectionError(String),
    InvalidMessage(String),
    EncryptionError(String),
    DatabaseError(String),
    SecurityChallengeMisMatch,
    Other(String),
}

pub mod msg;

pub struct Client{
    stream: TcpStream,
}

impl Client{
    pub fn new(stream_new: TcpStream) -> Self {
        Client { stream: stream_new }
    }

    pub async fn send(&mut self, data: Vec<u8>) -> Result<(), std::io::Error>{
        self.stream.write_all(&data).await
    }

    pub async fn recieve(&mut self) -> Result<Vec<u8>, std::io::Error>{
        let mut ret_val = Vec::new();
        let mut buffer = Vec::new();
        loop{
            match self.stream.read(&mut buffer).await{
                Ok(n) if n==0 => {
                    return Ok(ret_val);
                },
                Ok(_) => {
                    ret_val.append(&mut buffer);
                    buffer.clear();
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
}

pub struct User{
    asym_key: Option<AsymKey>,
    sym_key: Option<SymKey>,
    server_key: Arc<Mutex<AsymKey>>,
    client: RefCell<Client>,
    database: Database,
}

impl User{
    pub fn new(stream: TcpStream, server_key: Arc<Mutex<AsymKey>>, db: String) -> Self{
        User { 
            asym_key: None, 
            sym_key: None, 
            server_key,
            client: RefCell::new(Client::new(stream)),
            database: Database::new(db),
        }
    }

    pub async fn handshake(&mut self) -> Result<(), Error>{
        // This assumes the server public key is given elsewhere, likely through the invite string
        let en_msg = match self.client.borrow_mut().recieve().await{
            Ok(r) => r,
            Err(e) => return Err(Error::ConnectionError(format!("{:?}", e))),
        };
        let msg = match self.server_key.lock().await.decrypt(&en_msg){
            Ok(r) => r,
            Err(e) => return Err(Error::EncryptionError(format!("{:?}", e))),
        };
        let init_msg: InitialMessage = match serde_json::from_slice(&msg){
            Ok(r) => r,
            Err(e) => {
                let error_message = ErrorCode::new(0, format!("{:?}", e));
                let error_json = serde_json::to_string(&error_message).unwrap();
                self.client.borrow_mut().send(error_json.into_bytes()).await.unwrap();
                return Err(Error::InvalidMessage(format!("{:?}", e)));
            }
        };
        // we've made contact, now to see if this is the first time this server is seeing this user
        let uid = match self.database.retrieve_user_id(init_msg.username.clone()){
            Ok(r) => r,
            Err(e) => {
                if e == database::Error::NoUser{ //it is the first time, time to add a new entry
                    self.database.store_new_user(init_msg.username.clone()).unwrap()
                }else{ //something else happen, the database failed in some way
                    return Err(Error::DatabaseError(format!("{:?}", e)));
                }
            }
        };
        // Time to see if this user's machine has a key registered with us
        let pub_key = match self.database.retrieve_public_key(uid, init_msg.machine.clone()){
            Ok(r) => r, // there is a key, no problem
            Err(e) => { // There's no key, time to register a new machine for this user
                if e == database::Error::NoMachine{ // Get the new public key from the client
                    let pub_key_req = msg::PublicKeyRequest::new();
                    let pub_key_json = serde_json::to_string(&pub_key_req).unwrap();
                    self.client.borrow_mut().send(pub_key_json.into_bytes()).await.unwrap();
                    let pub_key_response = match self.client.borrow_mut().recieve().await{
                        Ok(r) => r,
                        Err(e) => return Err(Error::ConnectionError(format!("{:?}", e))),
                    };
                    let pub_key_decrypt = match self.server_key.lock().await.decrypt(&pub_key_response){
                        Ok(r) => r,
                        Err(e) => return Err(Error::EncryptionError(format!("{:?}", e))),
                    };
                    let pub_key_struct: PublicKeyResponse = match serde_json::from_slice(&pub_key_decrypt){
                        Ok(r) => r,
                        Err(e) => {
                            let error_message = ErrorCode::new(1, format!("{:?}", e));
                            let error_json = serde_json::to_string(&error_message).unwrap();
                            self.client.borrow_mut().send(error_json.into_bytes()).await.unwrap();
                            return Err(Error::InvalidMessage(format!("{:?}", e)));
                        }
                    };
                    self.database.store_new_pub_key(uid, init_msg.machine.clone(), pub_key_struct.pub_key.clone()).unwrap();
                    pub_key_struct.pub_key.clone()
                }else{
                    return Err(Error::Other(format!("{:?}", e)));
                }
            }
        };
        // We have the public key, time to store it in memory
        self.asym_key = Some(AsymKey::from_public_key(&pub_key));
        // Now to make sure this user actually have access to the private key
        let challenge_string = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
        let sec_chal = SecurityChallenge::new(challenge_string);
        let sec_json = serde_json::to_string(&sec_chal).unwrap();
        if let Some(key) = &self.asym_key{
            let sec_encrypt = key.encrypt(&sec_json.into_bytes()).unwrap();
            self.client.borrow_mut().send(sec_encrypt).await.unwrap();
        }
        let sec_response = match self.client.borrow_mut().recieve().await{
            Ok(r) => r,
            Err(e) => {
                return Err(Error::ConnectionError(format!("{:?}", e)));
            }
        };
        if let Some(key) = &self.asym_key{
            let sec_decrypt = match key.decrypt(&sec_response){
                Ok(r) => r,
                Err(e) => {
                    return Err(Error::EncryptionError(format!("{:?}", e)));
                }
            };
            let sec_json: SecurityChallenge = serde_json::from_slice(&sec_decrypt).unwrap();
            if sec_chal.challenge_text != sec_json.challenge_text{ // uh oh, the user didn't decode the challenge text correctly
                let sec_error = msg::ErrorCode::new(3, "Security test mismatch".to_string());
                let error_json = serde_json::to_string(&sec_error).unwrap();
                self.client.borrow_mut().send(error_json.into_bytes()).await.unwrap();
                return Err(Error::SecurityChallengeMisMatch);
            }
        }
        // The user is who they say they are, time to make a session key
        // See about making this it's own function to do it at a set time
        let sym_key = SymKey::from_rng();
        let sym_hex = format!("{:x?}", sym_key.key);
        let sym_exchange = msg::SymKeyExchange::new(sym_hex);
        let sym_json = serde_json::to_string(&sym_exchange).unwrap();
        if let Some(asm_key) = &self.asym_key{
            let sym_en = asm_key.encrypt(&sym_json.into_bytes()).unwrap();
            self.client.borrow_mut().send(sym_en).await.unwrap();
        }
        self.sym_key = Some(sym_key);
        Ok(())
    }
}

