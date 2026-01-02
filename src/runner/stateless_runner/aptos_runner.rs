use aptos_language_e2e_tests::executor::FakeExecutor;
use aptos_language_e2e_tests::account::Account;
use aptos_types::transaction::{
    EntryFunction, RawTransaction, SignedTransaction, TransactionPayload,
    TransactionArgument, TransactionStatus, TransactionOutput,
};
use aptos_types::chain_id::ChainId;
use move_core_types::transaction_argument;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::ident_str;
use move_core_types::language_storage::ModuleId;
use crate::runner::runner::Runner;
use crate::fuzzer::coverage::Coverage;
use crate::fuzzer::error::Error;
use crate::mutator::types::Type as FuzzerType;
use super::aptos_runner_utils::{
    generate_abi_from_source, generate_inputs, convert_move_value_to_aptos_arg,
};
use std::sync::{Arc, Mutex};

/// Helper to check if transaction status is Keep
fn is_kept(status: &TransactionStatus) -> bool {
    matches!(status, TransactionStatus::Keep(_))
}

pub struct StatelessAptosRunner {
    // We use a lazy initialization pattern - executor is created on first use
    // This is needed because FakeExecutor is not Send and must be created in the worker thread
    executor: Option<FakeExecutor>,
    target_module: String,
    target_function: FuzzerType,
    modules: Vec<Vec<u8>>,
    package_address: Option<AccountAddress>,
    account: Option<Account>,
    max_coverage: usize,
    contract_path: String,
    initialized: bool,
    // Sequence number for transactions - starts at 2 after publish (0) and fuzz_init (1)
    // For stateless fuzzing, we use the same sequence number since we don't apply write sets
    next_sequence_number: u64,
}

// Mark as Send - we'll initialize the FakeExecutor in the worker thread
unsafe impl Send for StatelessAptosRunner {}

impl StatelessAptosRunner {
    pub fn new(
        contract_path: &str,
        target_module: &str,
        target_function: &str,
        modules: Vec<Vec<u8>>,
    ) -> Self {
        // Extract ABI from source (this part is thread-safe)
        let (params, max_coverage) = generate_abi_from_source(
            contract_path,
            target_module,
            target_function,
        );
        println!("Target function '{}' has {} parameters, max_coverage: {}",
                 target_function, params.len(), max_coverage);
        for (i, p) in params.iter().enumerate() {
            println!("  param[{}]: {:?}", i, p);
        }

        // Create target function type
        let target_function_type = FuzzerType::Function(
            target_function.to_string(),
            params,
            None,
        );

        Self {
            executor: None,  // Will be initialized lazily in worker thread
            target_module: target_module.to_string(),
            target_function: target_function_type,
            modules,
            package_address: None,
            account: None,
            max_coverage,
            contract_path: contract_path.to_string(),
            initialized: false,
            next_sequence_number: 0,  // Will be set during initialization
        }
    }

    /// Initialize the executor - must be called from the worker thread
    fn ensure_initialized(&mut self) {
        if self.initialized {
            return;
        }

        println!("Initializing FakeExecutor in worker thread...");

        // Create FakeExecutor with genesis state (includes Aptos framework)
        let mut executor = FakeExecutor::from_head_genesis();

        // Create and fund an account
        let account = executor.create_accounts(1, 10_000_000_000, 0).pop().unwrap();
        let package_address = *account.address();

        println!("Created account at address: {:?}", package_address);

        // Track sequence number - publish uses 0
        let mut current_seq = 0u64;

        // Publish modules
        match Self::publish_modules(&mut executor, &account, &self.modules, package_address) {
            Ok(output) => {
                println!("Module publishing result status: {:?}", output.status());
                if is_kept(output.status()) {
                    current_seq = 1;  // Next sequence number after successful publish
                } else {
                    eprintln!("Warning: Module publishing was not kept!");
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to publish modules: {:?}", e);
            }
        }

        // Initialize with fuzz_init if it exists (optional) - uses sequence 1
        match Self::call_fuzz_init(&mut executor, &account, &self.target_module, package_address) {
            Ok(output) => {
                println!("fuzz_init called successfully");
                if is_kept(output.status()) {
                    current_seq = 2;  // Next sequence number after successful fuzz_init
                }
            }
            Err(e) => eprintln!("Note: fuzz_init not found or failed (this is OK): {:?}", e),
        }

        self.next_sequence_number = current_seq;
        println!("Next sequence number for fuzzing: {}", current_seq);

        self.executor = Some(executor);
        self.account = Some(account);
        self.package_address = Some(package_address);
        self.initialized = true;

        println!("FakeExecutor initialized successfully!");
    }

    fn publish_modules(
        executor: &mut FakeExecutor,
        account: &Account,
        modules: &[Vec<u8>],
        _package_address: AccountAddress,
    ) -> anyhow::Result<TransactionOutput> {
        let empty_metadata: Vec<u8> = vec![];

        // Create publish transaction payload using the code::publish_package_txn function
        let payload = TransactionPayload::EntryFunction(EntryFunction::new(
            ModuleId::new(
                AccountAddress::from_hex_literal("0x1").unwrap(),
                ident_str!("code").to_owned(),
            ),
            ident_str!("publish_package_txn").to_owned(),
            vec![],
            vec![
                bcs::to_bytes(&empty_metadata).unwrap(),
                bcs::to_bytes(&modules.to_vec()).unwrap(),
            ],
        ));

        // Create and sign transaction
        let raw_txn = RawTransaction::new(
            *account.address(),
            0, // sequence number
            payload,
            1_000_000, // max gas
            100, // gas unit price
            u64::MAX, // expiration timestamp
            ChainId::test(),
        );

        let signed_txn: SignedTransaction = raw_txn
            .sign(&account.privkey, account.pubkey.as_ed25519().expect("pubkey error").clone())?
            .into_inner();

        // Execute the transaction
        let outputs = executor.execute_block(vec![signed_txn])
            .map_err(|e| anyhow::anyhow!("Execution failed: {:?}", e))?;

        if let Some(output) = outputs.into_iter().next() {
            // Apply the write set if successful
            if is_kept(output.status()) {
                executor.apply_write_set(output.write_set());
            }
            Ok(output)
        } else {
            Err(anyhow::anyhow!("No transaction output"))
        }
    }

    fn call_fuzz_init(
        executor: &mut FakeExecutor,
        account: &Account,
        target_module: &str,
        package_address: AccountAddress,
    ) -> Result<TransactionOutput, Error> {
        let module_id = ModuleId::new(
            package_address,
            Identifier::new(target_module).map_err(|e| Error::Unknown {
                message: format!("Invalid module name: {}", e),
            })?,
        );

        let function_id = Identifier::new("fuzz_init").map_err(|e| Error::Unknown {
            message: format!("Invalid function name: {}", e),
        })?;

        let entry_function = EntryFunction::new(module_id, function_id, vec![], vec![]);
        let payload = TransactionPayload::EntryFunction(entry_function);

        let raw_txn = RawTransaction::new(
            *account.address(),
            1, // sequence number after publish
            payload,
            1_000_000,
            100,
            u64::MAX,
            ChainId::test(),
        );

        let signed_txn: SignedTransaction = raw_txn
            .sign(&account.privkey, account.pubkey.as_ed25519().expect("pubkey error").clone())
            .map_err(|e| Error::Unknown {
                message: format!("Failed to sign transaction: {}", e),
            })?
            .into_inner();

        let outputs = executor.execute_block(vec![signed_txn])
            .map_err(|e| Error::Unknown {
                message: format!("Execution failed: {:?}", e),
            })?;

        if let Some(output) = outputs.into_iter().next() {
            if is_kept(output.status()) {
                executor.apply_write_set(output.write_set());
            }
            Ok(output)
        } else {
            Err(Error::Unknown {
                message: "No transaction output".to_string(),
            })
        }
    }

    fn send_transaction(
        &mut self,
        target_function: &str,
        args: Vec<TransactionArgument>,
    ) -> Result<(TransactionStatus, u64), Error> {
        // Ensure executor is initialized
        self.ensure_initialized();

        let executor = self.executor.as_mut().unwrap();
        let account = self.account.as_ref().unwrap();
        let package_address = self.package_address.unwrap();

        let module_id = ModuleId::new(
            package_address,
            Identifier::new(self.target_module.as_str()).map_err(|e| Error::Unknown {
                message: format!("Invalid module name: {}", e),
            })?,
        );

        let function_id = Identifier::new(target_function).map_err(|e| Error::Unknown {
            message: format!("Invalid function name: {}", e),
        })?;

        let entry_function = EntryFunction::new(
            module_id,
            function_id,
            vec![],
            transaction_argument::convert_txn_args(&args)
        );
        let payload = TransactionPayload::EntryFunction(entry_function);

        // Create raw transaction
        // Use the correct sequence number for stateless fuzzing
        // Since we don't apply write sets, we use the same sequence number each time
        let seq_num = self.next_sequence_number;
        let raw_txn = RawTransaction::new(
            *account.address(),
            seq_num,
            payload,
            1_000_000, // max gas
            100, // gas unit price
            u64::MAX, // expiration
            ChainId::test(),
        );

        // Sign the transaction
        let signed_txn: SignedTransaction = raw_txn
            .sign(&account.privkey, account.pubkey.as_ed25519().expect("pubkey error").clone())
            .map_err(|e| Error::Unknown {
                message: format!("Failed to sign transaction: {}", e),
            })?
            .into_inner();

        // Execute the transaction
        let outputs = executor.execute_block(vec![signed_txn])
            .map_err(|e| Error::Unknown {
                message: format!("Transaction execution failed: {:?}", e),
            })?;

        // Extract result
        if let Some(output) = outputs.into_iter().next() {
            let gas_used: u64 = output.gas_used();
            // Note: In stateless mode, we don't apply write sets to preserve original state
            Ok((output.status().clone(), gas_used))
        } else {
            Err(Error::Unknown {
                message: "No transaction output".to_string(),
            })
        }
    }
}

impl Runner for StatelessAptosRunner {
    fn execute(&mut self, inputs: Vec<FuzzerType>)
        -> Result<(Option<Coverage>, u64), (Option<Coverage>, Error)> {
        // Convert inputs to MoveValues
        let move_values = generate_inputs(inputs.clone());

        // Convert MoveValues to TransactionArguments
        let args: Vec<TransactionArgument> = move_values
            .iter()
            .filter_map(|v| convert_move_value_to_aptos_arg(v))
            .collect();

        // Get target function name
        let function_name = if let FuzzerType::Function(name, _, _) = &self.target_function {
            name.clone()
        } else {
            return Err((None, Error::Unknown {
                message: "Invalid target function type".to_string(),
            }));
        };

        // Execute transaction
        match self.send_transaction(&function_name, args) {
            Ok((status, gas_used)) => {
                match &status {
                    TransactionStatus::Keep(exec_status) => {
                        // Success - return None for coverage, gas_used for feedback
                        Ok((None, gas_used))
                    },
                    TransactionStatus::Discard(status_code) => {
                        // Log first few discards to help debug
                        static DISCARD_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                        let count = DISCARD_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if count < 5 {
                            eprintln!("DEBUG: Transaction discarded with status: {:?}", status_code);
                        }
                        Err((None, Error::Unknown {
                            message: format!("Transaction discarded: {:?}", status_code),
                        }))
                    },
                    TransactionStatus::Retry => {
                        Err((None, Error::Unknown {
                            message: "Transaction retry requested".to_string(),
                        }))
                    }
                }
            },
            Err(e) => Err((None, e)),
        }
    }

    fn set_target_function(&mut self, function: &FuzzerType) {
        self.target_function = function.clone();
    }

    fn get_target_parameters(&self) -> Vec<FuzzerType> {
        if let FuzzerType::Function(_, params, _) = &self.target_function {
            params.clone()
        } else {
            vec![]
        }
    }

    fn get_target_module(&self) -> String {
        self.target_module.clone()
    }

    fn get_target_function(&self) -> FuzzerType {
        self.target_function.clone()
    }

    fn get_max_coverage(&self) -> usize {
        self.max_coverage
    }
}
