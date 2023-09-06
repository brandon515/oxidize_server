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
        InitialMessage, 
        PublicKeyResponse, 
        SecurityResponse,
    }, 
    database::{Database, self},
};

use std::sync::Arc;

use rand::distributions::{
    Alphanumeric,
    DistString,
};

use self::msg::{SecurityChallenge, SymEncryptedMsg};

#[derive(Debug)]
pub enum Error{
    ConnectionError(String),
    InvalidMessage(String),
    EncryptionError(crypto::Error),
    DatabaseError(String),
    SecurityChallengeMisMatch,
    VerificationError,
    Other(String),
}

pub mod msg;

pub struct Client{
    stream: TcpStream,
    server_key: Arc<Mutex<AsymKey>>,
    sym_key: Option<SymKey>,
}


impl Client{
    pub fn new(stream: TcpStream, server_key: Arc<Mutex<AsymKey>>) -> Self {
        Client { 
            stream,
            server_key, 
            sym_key: None,
        }
    }

    pub async fn send_unencrypted(&mut self, data: Vec<u8>){
        self.stream.write_all(&data).await.unwrap();
    }

    pub async fn send(&mut self, data: Vec<u8>) -> Result<(), Error>{
        if let Some(k) = &self.sym_key{
            match k.encrypt(&data) {
                Ok(r) => {
                    let msg = serde_json::to_string(&r).unwrap();
                    self.stream.write_all(&msg.as_bytes()).await.unwrap();
                    return Ok(());
                },
                Err(e) => {
                    return Err(Error::EncryptionError(e));
                }
            }
        }else{
            match self.server_key.lock().await.sign(&data){
                Ok(r) => {
                    let signed_message = msg::ServerMessage::new(data, r);
                    let signed_message_json = serde_json::to_string(&signed_message).unwrap();
                    self.stream.write_all(&signed_message_json.into_bytes()).await.unwrap();
                    return Ok(());
                },
                Err(e) => {
                    return Err(Error::EncryptionError(e));
                }
            }
        }
    }

    pub async fn recieve_unencrypted(&mut self) -> Result<Vec<u8>, Error>{
        let mut buffer = [0; 8];
        let mut size:usize = 0;
        match self.stream.read(&mut buffer).await{
            Ok(n) => if n <= 8 {
                println!("Number of Bytes Array: {:?}", buffer.clone());
                size = usize::from_be_bytes(buffer);
                println!("Number of Bytes: {}", size);
            },
            Err(e) => {
                return Err(Error::ConnectionError(format!("{:?}", e)));
            }
        }
        let mut bytes_recv = 0;
        let mut ret_val: Vec<u8> = Vec::new();
        loop{
            let mut byte_buffer: Vec<u8> = vec![0; 2048];
            match self.stream.read(&mut byte_buffer).await{
                Ok(n) if n == 0 => {
                    if size != 0 {
                        return Err(Error::ConnectionError(format!("Incorrect length for message.\
                        Expected: {}\
                        Received: {}", size, bytes_recv)));
                    }else{
                        return Err(Error::ConnectionError(format!("Connection from {:?} reset", self.stream.peer_addr().unwrap())))
                    }
                }
                Ok(n) => {
                    byte_buffer.truncate(n);
                    ret_val.extend(byte_buffer.iter());
                    println!("Data: {:?}", ret_val);
                    bytes_recv = bytes_recv+n;
                    println!("Bytes recieved: {}", bytes_recv);
                    if bytes_recv==size{
                        return Ok(ret_val);
                    }else{
                        byte_buffer.clear();
                        byte_buffer.resize(1024, 0);
                    }
                },
                Err(e) => {
                    return Err(Error::ConnectionError(format!("{:?}", e)));
                }
            }
        }
    }

    pub async fn recieve(&mut self) -> Result<Vec<u8>, Error>{
        let ret_val = self.recieve_unencrypted().await?;
        if let Some(k) = &self.sym_key{
            let en_msg_json: SymEncryptedMsg = match serde_json::from_slice(&ret_val){
                Ok(r) => r,
                Err(e) => {
                    return Err(Error::InvalidMessage(format!("{:?}", e)));
                },
            };
            match k.decrypt(&en_msg_json){
                Ok(r) => {
                    return Ok(r);
                },
                Err(e) => {
                    return Err(Error::EncryptionError(e));
                }
            }
        }else{
            match self.server_key.lock().await.decrypt(&ret_val){
                Ok(r) => Ok(r),
                Err(e) => Err(Error::EncryptionError(e))
            }
        }
    }
}

pub struct User{
    asym_key: Option<AsymKey>,
    client: Client,
    database: Database,
}

impl User{
  pub fn new(stream: TcpStream, server_key: Arc<Mutex<AsymKey>>, db: String) -> Self{
    User { 
      asym_key: None,
      client: Client::new(stream, server_key),
      database: Database::new(db),
    }
  }

  pub async fn handshake(&mut self) -> Result<(), Error>{
    // This assumes the server public key is given elsewhere, likely through the invite string
    let msg = match self.client.recieve().await{
      Ok(r) => r,
      Err(e) => return Err(Error::ConnectionError(format!("{:?}", e))),
    };
    let init_msg: InitialMessage = match serde_json::from_slice(&msg){
      Ok(r) => r,
      Err(e) => {
        let error_message = ErrorCode::new(0, format!("{:?}", e));
        let error_json = serde_json::to_string(&error_message).unwrap();
        self.client.send(error_json.into_bytes()).await.unwrap();
        return Err(Error::InvalidMessage(format!("{:?}", e)));
      }
    };
    println!("{:?}", init_msg);
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
          self.client.send(pub_key_json.into_bytes()).await.unwrap();
          let pub_key_response = match self.client.recieve_unencrypted().await{
            Ok(r) => r,
            Err(e) => return Err(Error::ConnectionError(format!("{:?}", e))),
          };
          let pub_key_struct: PublicKeyResponse = match serde_json::from_slice(&pub_key_response){
            Ok(r) => r,
            Err(e) => {
              let error_message = ErrorCode::new(1, format!("{:?}", e));
              let error_json = serde_json::to_string(&error_message).unwrap();
              self.client.send(error_json.into_bytes()).await.unwrap();
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
    println!("Public Key: {}", pub_key);
    // We have the public key, time to store it in memory
    self.asym_key = Some(AsymKey::from_public_key(&pub_key));
    // Now to make sure this user actually have access to the private key
    let challenge_string = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
    if let Some(key) = &self.asym_key{
      let sec_encrypt = key.encrypt(&challenge_string.clone().into_bytes()).unwrap();
      let sec_chal = SecurityChallenge::new(sec_encrypt);
      let sec_json = serde_json::to_string(&sec_chal).unwrap();
      self.client.send(sec_json.into_bytes()).await?;
    }
    let sec_response = self.client.recieve_unencrypted().await?;
    //println!("{}", String::from_utf8(sec_response.clone()).unwrap());
    let sec_json: SecurityResponse = serde_json::from_slice(&sec_response).unwrap();
    if let Some(key) = &self.asym_key{
      println!("Sent String: {}\nRecieved String: {}", challenge_string, sec_json.challenge_text);
      if key.verify(&Vec::from(sec_json.challenge_text.as_bytes()), &sec_json.signature).unwrap() == false{
        return Err(Error::VerificationError);
      }
      if challenge_string != sec_json.challenge_text{ // uh oh, the user didn't decode the challenge text correctly
        let sec_error = msg::ErrorCode::new(3, "Security test mismatch".to_string());
        let error_json = serde_json::to_string(&sec_error).unwrap();
        self.client.send(error_json.into_bytes()).await.unwrap();
        return Err(Error::SecurityChallengeMisMatch);
      }
    }
    // The user is who they say they are, time to make a session key
    // See about making this it's own function to do it at a set time
    let sym_key = SymKey::from_rng();
    if let Some(asm_key) = &self.asym_key{
      let sym_en = asm_key.encrypt(&sym_key.key).unwrap();
      let sym_exchange = msg::SymKeyExchange::new(sym_en.clone());
      let sym_json = serde_json::to_string(&sym_exchange).unwrap();
      self.client.send(sym_json.into_bytes()).await?;
    }
    self.client.sym_key = Some(sym_key);
    Ok(())
  }
}

