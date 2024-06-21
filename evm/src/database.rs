//use alloy_primitives::{Address, B256, U256};
use bytes::Bytes;
use revm::{
    db::{CacheDB, DatabaseRef},
    primitives::{AccountInfo, Address, Bytecode, B256, U256},
    InMemoryDB,
};
use statedb::STATE_DB;

pub type VmState = CacheDB<StateDB>;

#[derive(Clone)]
pub struct StateDB;

impl StateDB {
    pub fn new() -> StateDB {
        StateDB
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        match STATE_DB.clone().lock().get(key) {
            Ok(v) => Some(v),
            Err(_) => None,
        }
    }

    fn set(&self, key: &[u8], value: &[u8]) -> Result<(), ()> {
        match STATE_DB.clone().lock().put(key, value) {
            Ok(v) => Ok(v),
            Err(_) => Err(()),
        }
    }
}

impl DatabaseRef for StateDB {
    type Error = ();

    fn basic(&self, address: Address) -> std::result::Result<Option<AccountInfo>, Self::Error> {
        let key = address.as_slice();
        match self.get(key) {
            Some(v) => {
                let account = AccountInfo::from(v);
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    fn code_by_hash(&self, code_hash: B256) -> std::result::Result<Bytecode, Self::Error> {
        let key = code_hash.as_slice();
        match self.get(key) {
            Some(v) => {
                let code = Bytecode::from(v);
                return Ok(code);
            }
            None => return Ok(None),
        }
    }

    fn storage(&self, address: Address, index: U256) -> std::result::Result<U256, Self::Error> {
        let key = address.as_slice();
        let value = index.as_le_slice();

        match self.set(key, value) {
            Some(v) => {
                let account = AccountInfo::from(v);
                let value = account.storage[index.as_usize];
                return Ok(value);
            }
            None => return Ok(None),
        }
    }

    fn block_hash(&self, number: U256) -> std::result::Result<B256, Self::Error> {
        let key = number.as_le_slice();
        match self.get(&key) {
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
