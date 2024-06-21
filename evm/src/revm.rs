use bytes::Bytes;
use revm::{
    db::{AccountState, CacheDB, DatabaseRef},
    primitives::{
        hash_map::{self, Entry},
        Account, AccountInfo, Address, AnalysisKind, BlockEnv, CfgEnv, EVMError, Env,
        ExecutionResult, Output, ResultAndState, TransactTo, TxEnv, B256, KECCAK_EMPTY, U256,
    },
    Database, InMemoryDB, EVM,
};
use std::collections::BTreeMap;

pub struct EvmVM {
    evm: EVM<InMemoryDB>,
}

impl EvmVM {
    pub(crate) fn new_memory() -> Self {
        let mut evm = EVM::new();
        let memory_db = InMemoryDB::default();
        evm.database(memory_db);

        EvmVM { evm }
    }

    pub(crate) fn execute(
        &mut self,
        index: usize,
        transaction: &SignedTransaction,
        post_state: &mut PostState,
    ) -> std::result::Result<(), VmError> {
        self.fill_tx_env(&transaction)?;

        // main execution.
        let out = self.evm.transact();
        let ret_and_state = match out {
            Ok(ret_and_state) => ret_and_state,
            Err(e) => {
                return Err(VmError::VMExecuteError {
                    hash: transaction.hash_hex(),
                    message: format!("{:?}", e),
                });
            }
        };

        let ResultAndState { result, state } = ret_and_state;
        let (output, contract_address) = match result.clone() {
            ExecutionResult::Success { output, .. } => match output {
                Output::Call(value) => (Some(value.into()), None),
                Output::Create(value, address) => (Some(value.into()), address),
            },
            ExecutionResult::Revert { gas_used, output } => {
                println!(
                    "Execution reverted: gas used: {}, output: {:?}",
                    gas_used, output
                );
                (Some(output.into()), None)
            }
            ExecutionResult::Halt { reason, gas_used } => {
                println!("Execution halted: {:?}, gas used: {}", reason, gas_used);
                (None, None)
            }
        };

        let blocknum = match u64::try_from(self.evm.env.block.number) {
            Ok(n) => n,
            Err(e) => {
                return Err(VmError::InternalError {
                    error: format!("{:?}", e),
                });
            }
        };
        self.commit_changes(blocknum, state, true, post_state);

        post_state.add_receipt(
            blocknum,
            Receipt {
                index: index,
                // Success flag was added in `EIP-658: Embedding transaction status code in
                // receipts`.
                success: result.is_success(),
                gas_used: result.gas_used(),
                contract_address: contract_address,
                output: output,
                // convert to reth log
                logs: result.into_logs().into_iter().collect(),
                description: None,
            },
        );

        Ok(())
    }

    pub fn to_post_acc(revm_acc: &AccountInfo) -> PostAccount {
        let code_hash = revm_acc.code_hash;
        PostAccount {
            balance: revm_acc.balance,
            nonce: revm_acc.nonce,
            bytecode_hash: (code_hash != KECCAK_EMPTY).then_some(code_hash),
        }
    }

    fn commit_changes(
        &mut self,
        block_number: u64,
        changes: hash_map::HashMap<B160, RevmAccount>,
        has_state_clear_eip: bool,
        post_state: &mut PostState,
    ) {
        let db = self.db();
        Self::commit_state_changes(db, post_state, block_number, changes, has_state_clear_eip);
    }

    fn commit_state_changes(
        db: &mut VmState,
        post_state: &mut PostState,
        block_number: u64,
        changes: hash_map::HashMap<B160, RevmAccount>,
        has_state_clear_eip: bool,
    ) {
        // iterate over all changed accounts
        for (address, account) in changes {
            if account.is_destroyed {
                // get old account that we are destroying.
                let db_account = match db.accounts.entry(address) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(_entry) => {
                        panic!("Left panic to critically jumpout if happens, as every account should be hot loaded.");
                    }
                };

                let account_exists = !matches!(db_account.account_state, AccountState::NotExisting);
                if account_exists {
                    // Insert into `change` a old account and None for new account
                    // and mark storage to be wiped
                    post_state.destroy_account(
                        block_number,
                        address,
                        Self::to_post_acc(&db_account.info),
                    );
                }

                // clear cached DB and mark account as not existing
                db_account.storage.clear();
                db_account.account_state = AccountState::NotExisting;
                db_account.info = AccountInfo::default();

                continue;
            } else {
                // check if account code is new or old.
                // does it exist inside cached contracts if it doesn't it is new bytecode that
                // we are inserting inside `change`
                if let Some(ref code) = account.info.code {
                    if !code.is_empty() && !db.contracts.contains_key(&account.info.code_hash) {
                        db.contracts.insert(account.info.code_hash, code.clone());
                        post_state.add_bytecode(account.info.code_hash, address, code.clone());
                    }
                }

                // get old account that is going to be overwritten or none if it does not exist
                // and get new account that was just inserted. new account mut ref is used for
                // inserting storage
                let cached_account = match db.accounts.entry(address) {
                    Entry::Vacant(entry) => {
                        let entry = entry.insert(Default::default());
                        entry.info = account.info.clone();
                        entry.account_state = AccountState::NotExisting; // we will promote account state down the road 在未来提升帐户状态
                        let new_account = Self::to_post_acc(&entry.info);

                        #[allow(clippy::nonminimal_bool)]
                        // If account was touched before state clear EIP, create it.
                        if !has_state_clear_eip ||
                        // If account was touched after state clear EIP, create it only if it is not empty.
                        (has_state_clear_eip && !new_account.is_empty())
                        {
                            post_state.create_account(block_number, address, new_account);
                        }

                        entry
                    }
                    Entry::Occupied(entry) => {
                        let entry = entry.into_mut();

                        let old_account = Self::to_post_acc(&entry.info);
                        let new_account = Self::to_post_acc(&account.info);

                        let account_non_existent =
                            matches!(entry.account_state, AccountState::NotExisting);

                        // Before state clear EIP, create account if it doesn't exist
                        if (!has_state_clear_eip && account_non_existent)
                        // After state clear EIP, create account only if it is not empty
                        || (has_state_clear_eip && entry.info.is_empty() && !new_account.is_empty())
                        {
                            post_state.create_account(block_number, address, new_account);
                        } else if old_account != new_account {
                            post_state.change_account(
                                block_number,
                                address,
                                Self::to_post_acc(&entry.info),
                                new_account,
                            );
                        } else if has_state_clear_eip
                            && new_account.is_empty()
                            && !account_non_existent
                        {
                            // The account was touched, but it is empty, so it should be deleted.
                            // This also deletes empty accounts which were created before state clear
                            // EIP.
                            post_state.destroy_account(block_number, address, new_account);
                        }

                        entry.info = account.info.clone();
                        entry
                    }
                };

                cached_account.account_state = if account.storage_cleared {
                    cached_account.storage.clear();
                    AccountState::StorageCleared
                } else if cached_account.account_state.is_storage_cleared() {
                    // the account already exists and its storage was cleared, preserve its previous
                    // state
                    AccountState::StorageCleared
                } else if has_state_clear_eip
                    && matches!(cached_account.account_state, AccountState::NotExisting)
                    && cached_account.info.is_empty()
                {
                    AccountState::NotExisting
                } else {
                    AccountState::Touched
                };

                // Insert storage.
                let mut storage_changeset = BTreeMap::new();

                // insert storage into new db account.
                cached_account
                    .storage
                    .extend(account.storage.into_iter().map(|(key, value)| {
                        if value.is_changed() {
                            storage_changeset
                                .insert(key, (value.original_value(), value.present_value()));
                        }
                        (key, value.present_value())
                    }));

                // Insert into change.
                if !storage_changeset.is_empty() {
                    post_state.change_storage(block_number, address, storage_changeset);
                }
            }
        }
    }

    pub fn call<DB: Database>(
        &mut self,
        env: Env,
        db: DB,
    ) -> std::result::Result<ResultAndState, EVMError<DB::Error>> {
        let mut evm = EVM::with_env(env);
        evm.database(db);
        evm.transact()
    }
}
