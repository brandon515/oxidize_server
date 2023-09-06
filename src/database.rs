use sqlite::{
    ConnectionWithFullMutex,
    State,
};

#[derive(Debug, PartialEq)]
pub enum Error{
    NoUser,
    NoMachine,
    Other(String),
}

pub struct Database{
    connection: ConnectionWithFullMutex,
}

impl Database{
  pub fn new(database_name: String) -> Self{
    let connection = sqlite::Connection::open_with_full_mutex(database_name).unwrap();
    Database { 
      connection,
    }
  }

  pub fn retrieve_user_id(&self, username: String) -> Result<i64, Error> {
    let statement_text = "SELECT id FROM names WHERE username = :username";
    let mut statement = self.connection.prepare(statement_text).unwrap();
    if let Err(e) = statement.bind::<(_, sqlite::Value)>((":username", username.into())){
      return Err(Error::Other(format!("{:?}", e)));
    }
    if let Ok(State::Row) = statement.next() { // username exists
      return Ok(statement.read::<i64,_>("id").unwrap())
    }else{
      return Err(Error::NoUser);
    }
  }

  pub fn retrieve_public_key(&self, user_id: i64, machine: String) -> Result<String, Error>{
    let statement_text = "SELECT pub_key FROM keys WHERE machine = :machine AND user_id = :user_id";
    let mut statement = self.connection.prepare(statement_text).unwrap();
    if let Err(e) = statement.bind::<&[(_, sqlite::Value)]>(&[
      (":user_id", user_id.into()),
      (":machine", machine.into()),
    ][..]){
      return Err(Error::Other(format!("{:?}", e)));
    }
    if let Ok(State::Row) = statement.next() {
      return Ok(statement.read::<String,_>("pub_key").unwrap());
    }else{
      return Err(Error::NoMachine);
    }
  }

  pub fn store_new_user(&self, username: String) -> Result<i64, Error>{
    let statement_text = "INSERT INTO names(username) VALUES(:username) RETURNING id";
    let mut statement = self.connection.prepare(statement_text).unwrap();
    if let Err(e) = statement.bind::<&[(_, sqlite::Value)]>(&[
      (":username", username.into()),
    ][..]){
      return Err(Error::Other(format!("{:?}", e)));
    }
    let res = statement.next();
    if let Ok(State::Row) = res {
      return Ok(statement.read::<i64,_>("id").unwrap());
    }else if let Err(e) = res{
      return Err(Error::Other(format!("{:?}", e)));
    }else{
      return Err(Error::Other("SQLite did not return an ID".to_string()));
    }
  }
  pub fn store_new_pub_key(&self, user_id: i64, machine: String, pub_key: String) -> Result<(), Error>{
    let statement_text = "INSERT INTO keys(pub_key, machine, user_id) VALUES(:pub_key, :machine, :user_id)";
    let mut statement = self.connection.prepare(statement_text).unwrap();
    if let Err(e) = statement.bind::<&[(_, sqlite::Value)]>(&[
      (":user_id", user_id.into()),
      (":machine", machine.into()),
      (":pub_key", pub_key.into()),
    ][..]){
      return Err(Error::Other(format!("{:?}", e)));
    }else{
      return Ok(());
    }
  }
}