use sqlite::{
    ConnectionWithFullMutex,
    State,
};

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

    pub fn retrieve_user_id(&mut self, username: String) -> Result<i64, Error> {
        let statement_text = "SELECT id FROM names WHERE username = :username";
        let mut statement = self.connection.prepare(statement_text).unwrap();
        statement.bind::<(_, sqlite::Value)>((":username", username.into())).unwrap();
        if let Ok(State::Row) = statement.next() { // username exists
            return Ok(statement.read::<i64,_>("id").unwrap())
        }else{
            return Err(Error::NoUser);
        }
    }

    pub fn retrieve_public_key(&mut self, user_id: i64, machine: String) -> Result<String, Error>{
        let statement_text = "SELECT pub_key FROM keys WHERE machine = :machine AND user_id = :user_id";
        let mut statement = self.connection.prepare(statement_text).unwrap();
        statement.bind::<&[(_, sqlite::Value)]>(&[
            (":user_id", user_id.into()),
            (":machine", machine.into()),
        ][..]).unwrap();
        if let Ok(State::Row) = statement.next() {
            return Ok(statement.read::<String,_>("pub_key").unwrap());
        }else{
            return Err(Error::NoMachine);
        }
    }
}