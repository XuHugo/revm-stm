use bytes::Bytes;

use revm::{
    db::{CacheDB, DatabaseRef},
    primitives::{AccountInfo, Bytecode, B160, B256, U256},
};

use std::convert::TryInto;
use types::error::VmError;

pub type VmState = CacheDB<StateDB>;

#[derive(Clone)]
pub struct StateDB;

impl StateDB {
    pub fn new() -> StateDB {
        StateDB
    }

    fn get(&self, key: &[u8]) -> Option<&[u8]> {
        match STATE_DB.clone().lock().get(key) {
            Ok(v) => Some(v),
            Err(_) => None,
        }
    }

    fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        match STATE_DB.clone().lock().put(key, value) {
            Ok(v) => Ok(v),
            Err(_) => Err("set error".into()),
        }
    }
}

impl DatabaseRef for State {
    type Error = VmError;

    fn basic(&self, address: B160) -> std::result::Result<Option<AccountInfo>, Self::Error> {
        let key = address.as_bytes;
        let result = self.get(&key)?;
        match result {
            Some(v) => {
                let account = AccountInfo::from(v);
                return Ok(Some(account));
            }
            None => return Ok(None),
        }
    }

    fn code_by_hash(&self, code_hash: B256) -> std::result::Result<Bytecode, Self::Error> {
        let key = code_hash.as_bytes;
        let result = self.get(&key)?;
        match result {
            Some(v) => {
                let code = Bytecode::from(v);
                return Ok(Some(code));
            }
            None => return Ok(None),
        }
    }

    fn storage(&self, address: B160, index: U256) -> std::result::Result<U256, Self::Error> {
        let key = address.as_bytes;
        let value = index.as_bytes;
        let result = self.set(&key, &value)?;

        match result {
            Some(v) => {
                let account = AccountInfo::from(v);
                let value = account.storage[index.as_usize];
                return Ok(Some(value));
            }
            None => return Ok(None),
        }
    }

    fn block_hash(&self, number: U256) -> std::result::Result<B256, Self::Error> {
        let key = number.as_bytes;
        let result = self.get(&key)?;
        match result {
            Some(v) => {
                let hash = B256::from(v);
                return Ok(Some(hash));
            }
            None => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::primitives::U256;

    #[test]
    fn u256_test() {
        let value = U256::from(10000000);
    }
}
