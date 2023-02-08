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
    database::Database,
};

use std::{
    cell::{
        RefCell
    }, 
    sync::Arc,
};

use sqlite::ConnectionWithFullMutex;

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

pub struct User<'a>{
    asym_key: Option<AsymKey>,
    sym_key: Option<SymKey>,
    server_key: Arc<Mutex<AsymKey>>,
    client: RefCell<Client>,
    database: Database<'a>,
}

impl User<'_>{
    pub fn new(stream: TcpStream, server_key: Arc<Mutex<AsymKey>>, db: String) -> Self{
        User { 
            asym_key: None, 
            sym_key: None, 
            server_key,
            client: RefCell::new(Client::new(stream)),
            database: Database::new(db)
        }
    }
    pub async fn handshake(&self) -> Result<(), crypto::Error>{
        let en_msg = match self.client.borrow_mut().recieve().await{
            Ok(r) => r,
            Err(e) => return Err(crypto::Error::Other(format!("{:?}", e))),
        };
        let msg = match self.server_key.lock().await.decrypt(&en_msg){
            Ok(r) => r,
            Err(e) => return Err(e),
        };
        let init_msg: msg::InitialMessage = match serde_json::from_slice(&msg){
            Ok(r) => r,
            Err(e) => return Err(crypto::Error::Other(format!("{:?}", e))),
        };
        unimplemented!();
    }
    pub async fn tick(&self) -> Result<bool, tokio::io::Error>{
        unimplemented!();
    }
}

