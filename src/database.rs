use sqlite::{
    ConnectionWithFullMutex,
    Statement,
};

enum Error{
    NoUser,
    NoMachine,
    Other(String),
}

pub struct Database<'a>{
    connection: ConnectionWithFullMutex,
    public_key_statement: Statement<'a>,
    user_id_statement: Statement<'a>,
}

impl Database<'_>{
    pub fn new(database_name: String) -> Self{
        let connection = sqlite::Connection::open_with_full_mutex(database_name).unwrap();
        let statement_text = "SELECT pub_key FROM keys WHERE machine = :machine AND user_id = :user_id";
        let public_key_statement = connection.prepare(statement_text).unwrap();
        let statement_text = "SELECT id FROM names WHERE username = :username";
        let user_id_statement = connection.prepare(statement_text).unwrap();
        Database { 
            connection, 
            public_key_statement,
            user_id_statement,
        }
    }

    pub fn retrieve_user_id(&self, username: String) -> Result<u32, Error> {
        self.user_id_statement.bind((":username", &username))?;
        unimplemented!()
    }

    pub fn retrieve_public_key(&self, username: String, machine: String) -> Result<String, Error>{
        unimplemented!()
    }
}