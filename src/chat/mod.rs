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
        self,
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

#[derive(Debug, PartialEq)]
pub enum Error{
    ConnectionError(String),
    InvalidMessage(String),
    EncryptionError(String),
    DatabaseError(String),
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
        let uid = match self.database.retrieve_user_id(init_msg.username.clone()){
            Ok(r) => r,
            Err(e) => {
                if e == database::Error::NoUser{
                    self.database.store_new_user(init_msg.username.clone()).unwrap()
                }else{
                    return Err(Error::DatabaseError(format!("{:?}", e)));
                }
            }
        };
        let pub_key = match self.database.retrieve_public_key(uid, init_msg.machine.clone()){
            Ok(r) => r,
            Err(e) => {
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
        self.asym_key = Some(AsymKey::from_public_key(&pub_key));
        Ok(())
    }
}

