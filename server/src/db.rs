use std::sync::Arc;

use log::{info, trace};

use crate::User;

pub struct Db(Arc<sled::Db>);

impl Clone for Db {
    fn clone(&self) -> Self {
        Db(Arc::clone(&self.0))
    }
}

impl Db {
    pub fn open(string: &str) -> Db {
        info!("Opening DB");

        Db(Arc::new(
            sled::open(string).expect("the database to be available"),
        ))
    }

    pub fn contains(&self, username: &str) -> Result<bool, anyhow::Error> {
        trace!("Checking if {username} exists");

        Ok(self.0.contains_key(username.as_bytes())?)
    }

    pub fn add(&self, user: &User) -> Result<(), anyhow::Error> {
        trace!("Adding user `{}` to the database", &user.username);

        self.0
            .insert(user.username.as_bytes(), serde_json::to_vec(user)?)?;

        Ok(())
    }

    pub fn get(&self, username: &str) -> Result<Option<User>, anyhow::Error> {
        trace!("Getting user `{username}` from the database");

        match self.0.get(username.as_bytes())? {
            Some(v) => Ok(serde_json::from_slice(&v)?),
            None => Ok(None),
        }
    }
}
