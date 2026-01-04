use aptos_language_e2e_tests::executor::FakeExecutor;
use aptos_language_e2e_tests::account::Account;
use aptos_types::transaction::{
    EntryFunction, TransactionPayload,
    TransactionArgument, TransactionStatus, TransactionOutput, ExecutionStatus,
};
use move_core_types::transaction_argument;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;
use move_binary_format::{CompiledModule, access::ModuleAccess};
use std::collections::HashMap;
use crate::runner::aptos_helpers::registry::build_helpers;
use crate::runner::aptos_helpers::AptosHelper;
use crate::runner::runner::Runner;
use crate::fuzzer::coverage::Coverage;
use crate::fuzzer::error::Error;
use crate::mutator::types::Type as FuzzerType;
use super::aptos_runner_utils::{
    generate_abi_from_source, generate_inputs, convert_move_value_to_aptos_arg,
};
use aptos_cached_packages::aptos_stdlib::code_publish_package_txn;

/// Helper to check if transaction status is Keep
fn is_kept(status: &TransactionStatus) -> bool {
    matches!(status, TransactionStatus::Keep(_))
}

// Publish must be signed by the module's declared address; derive it from bytecode.
fn resolve_package_address(
    modules: &[Vec<u8>],
    target_module: &str,
) -> Option<AccountAddress> {
    let mut first_address = None;
    for bytes in modules {
        if let Ok(module) = CompiledModule::deserialize(bytes) {
            let addr: AccountAddress = *module.address();
            if first_address.is_none() {
                first_address = Some(addr);
            }
            if module.name().as_str() == target_module {
                return Some(addr);
            }
        }
    }
    first_address
}


pub struct StatelessAptosRunner {
    // We use a lazy initialization pattern - executor is created on first use
    // This is needed because FakeExecutor is not Send and must be created in the worker thread
    executor: Option<FakeExecutor>,
    target_module: String,
    target_function: FuzzerType,
    modules: Vec<Vec<u8>>,
    package_metadata: Vec<u8>,
    package_address: Option<AccountAddress>,
    account: Option<Account>,
    max_coverage: usize,
    contract_path: String,
    initialized: bool,
    // Sequence number for transactions - starts at 2 after publish (0) and fuzz_init (1)
    // For stateless fuzzing, we use the same sequence number since we don't apply write sets
    next_sequence_number: u64,
    aptos_helpers: HashMap<String, String>,
    helper_instances: HashMap<String, Box<dyn AptosHelper>>,
}

// Mark as Send - we'll initialize the FakeExecutor in the worker thread
unsafe impl Send for StatelessAptosRunner {}

impl StatelessAptosRunner {
    fn helper_for_function(&self, function_name: &str) -> Option<&dyn AptosHelper> {
        let key = format!("{}::{}", self.target_module, function_name);
        let helper_name = self.aptos_helpers.get(&key)?;
        self.helper_instances.get(helper_name).map(|h| h.as_ref())
    }

    pub fn new(
        contract_path: &str,
        target_module: &str,
        target_function: &str,
        package_metadata: Vec<u8>,
        modules: Vec<Vec<u8>>,
        seed: u64,
        aptos_helpers: HashMap<String, String>,
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

        let helper_instances = build_helpers(&aptos_helpers, seed);

        Self {
            executor: None,  // Will be initialized lazily in worker thread
            target_module: target_module.to_string(),
            target_function: target_function_type,
            modules,
            package_metadata,
            package_address: None,
            account: None,
            max_coverage,
            contract_path: contract_path.to_string(),
            initialized: false,
            next_sequence_number: 0,  // Will be set during initialization
            aptos_helpers,
            helper_instances,
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

        let package_address = resolve_package_address(&self.modules, &self.target_module);
        let account = if let Some(addr) = package_address {
            executor.new_account_at(addr)
        } else {
            executor.create_accounts(1, 10_000_000_000, 0).pop().unwrap()
        };
        let package_address = *account.address();

        println!("Created account at address: {:?}", package_address);

        // Track sequence number - publish uses 0
        let mut current_seq = 0u64;

        // Publish modules
        match Self::publish_modules(
            &mut executor,
            &account,
            &self.modules,
            package_address,
            &self.package_metadata,
        ) {
            Ok(output) => {
                println!("Module publishing result status: {:?}", output.status());
                match output.status() {
                    TransactionStatus::Keep(exec_status) => match exec_status {
                        ExecutionStatus::Success => {
                            println!("Module publishing succeeded!");
                            current_seq = 1;
                        }
                        _ => {
                            eprintln!("Module publishing failed with execution status: {:?}", exec_status);
                            eprintln!("Events: {:?}", output.events());
                        }
                    },
                    TransactionStatus::Discard(status) => {
                        eprintln!("Module publishing discarded: {:?}", status);
                    }
                    TransactionStatus::Retry => {
                        eprintln!("Module publishing needs retry");
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to publish modules: {:?}", e);
            }
        }

        if current_seq > 0 {
            for helper in self.helper_instances.values() {
                if let Some(args) = helper.initialize_args(*account.address()) {
                    match self.call_initialize_helper(
                        &mut executor,
                        &account,
                        package_address,
                        current_seq,
                        args,
                    ) {
                        Ok(output) => match output.status() {
                            TransactionStatus::Keep(ExecutionStatus::Success) => {
                                executor.apply_write_set(output.write_set());
                                current_seq += 1;
                            }
                            _ => eprintln!("initialize failed with status: {:?}", output.status()),
                        },
                        Err(e) => eprintln!("initialize failed: {:?}", e),
                    }
                }
            }
        }

        // Initialize with fuzz_init if it exists (optional)
        match Self::call_fuzz_init(
            &mut executor,
            &account,
            &self.target_module,
            package_address,
            current_seq,
        ) {
            Ok(output) => {
                println!("fuzz_init called successfully");
                if is_kept(output.status()) {
                    current_seq += 1;
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
        package_metadata: &[u8],
    ) -> anyhow::Result<TransactionOutput> {
        // Build proper package metadata
        let payload = code_publish_package_txn(package_metadata.to_vec(), modules.to_vec());

        // Use account's transaction helper
        let signed_txn = account
            .transaction()
            .payload(payload)
            .sequence_number(0)
            .gas_unit_price(100)
            .sign();

        // Execute the transaction
        let output = executor.execute_transaction(signed_txn);

        // Apply the write set if successful
        if is_kept(output.status()) {
            executor.apply_write_set(output.write_set());
        }
        Ok(output)
    }

    fn call_fuzz_init(
        executor: &mut FakeExecutor,
        account: &Account,
        target_module: &str,
        package_address: AccountAddress,
        seq_num: u64,
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

        // Use account's transaction helper
        let signed_txn = account
            .transaction()
            .payload(payload)
            .sequence_number(seq_num)
            .gas_unit_price(100)
            .sign();

        let output = executor.execute_transaction(signed_txn);

        if is_kept(output.status()) {
            executor.apply_write_set(output.write_set());
        }
        Ok(output)
    }

    fn call_initialize_helper(
        &self,
        executor: &mut FakeExecutor,
        account: &Account,
        package_address: AccountAddress,
        seq_num: u64,
        args: Vec<Vec<u8>>,
    ) -> Result<TransactionOutput, Error> {
        let module_id = ModuleId::new(
            package_address,
            Identifier::new(self.target_module.as_str()).map_err(|e| Error::Unknown {
                message: format!("Invalid module name: {}", e),
            })?,
        );

        let function_id = Identifier::new("initialize").map_err(|e| Error::Unknown {
            message: format!("Invalid function name: {}", e),
        })?;

        let entry_function = EntryFunction::new(module_id, function_id, vec![], args);
        let payload = TransactionPayload::EntryFunction(entry_function);

        let signed_txn = account
            .transaction()
            .payload(payload)
            .sequence_number(seq_num)
            .gas_unit_price(100)
            .sign();

        Ok(executor.execute_transaction(signed_txn))
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

        // Use account's transaction helper
        // Use the correct sequence number for stateless fuzzing
        // Since we don't apply write sets, we use the same sequence number each time
        let seq_num = self.next_sequence_number;
        let signed_txn = account
            .transaction()
            .payload(payload)
            .sequence_number(seq_num)
            .gas_unit_price(100)
            .sign();

        // Execute the transaction
        let output = executor.execute_transaction(signed_txn);

        let gas_used: u64 = output.gas_used();
        // Note: In stateless mode, we don't apply write sets to preserve original state
        Ok((output.status().clone(), gas_used))
    }
}

impl Runner for StatelessAptosRunner {
    fn execute(&mut self, inputs: Vec<FuzzerType>)
        -> Result<(Option<Coverage>, u64), (Option<Coverage>, Error)> {
        let function_name = if let FuzzerType::Function(name, _, _) = &self.target_function {
            name.clone()
        } else {
            return Err((None, Error::Unknown {
                message: "Invalid target function type".to_string(),
            }));
        };

        let adjusted_inputs = if let Some(helper) = self.helper_for_function(&function_name) {
            helper.transform_inputs(&inputs).unwrap_or_else(|| inputs.clone())
        } else {
            inputs.clone()
        };

        // Convert inputs to MoveValues
        let move_values = generate_inputs(adjusted_inputs);

        // Convert MoveValues to TransactionArguments
        let args: Vec<TransactionArgument> = move_values
            .iter()
            .filter_map(|v| convert_move_value_to_aptos_arg(v))
            .collect();

        // Trace: Log inputs for each execution (module::function format)
        eprintln!("TRACE: {}::{}({:?})", self.target_module, function_name, args);

        // Execute transaction
        match self.send_transaction(&function_name, args) {
            Ok((status, gas_used)) => {
                match &status {
                    TransactionStatus::Keep(exec_status) => {
                        eprintln!("  -> OK (gas: {}, status: {:?})", gas_used, exec_status);
                        Ok((None, gas_used))
                    },
                    TransactionStatus::Discard(status_code) => {
                        eprintln!("  -> DISCARDED: {:?}", status_code);
                        Err((None, Error::Unknown {
                            message: format!("Transaction discarded: {:?}", status_code),
                        }))
                    },
                    TransactionStatus::Retry => {
                        eprintln!("  -> RETRY");
                        Err((None, Error::Unknown {
                            message: "Transaction retry requested".to_string(),
                        }))
                    }
                }
            },
            Err(e) => {
                eprintln!("  -> ERROR: {:?}", e);
                Err((None, e))
            },
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
