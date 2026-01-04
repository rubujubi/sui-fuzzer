#[cfg(feature = "aptos")]
use aptos_language_e2e_tests::{
    account::Account,
    executor::FakeExecutor,
};
#[cfg(feature = "aptos")]
use aptos_types::transaction::{
    EntryFunction,
    TransactionPayload,
    TransactionArgument,
    TransactionStatus,
    TransactionOutput,
    ExecutionStatus,
};
#[cfg(feature = "aptos")]
use move_core_types::{
    account_address::AccountAddress,
    value::{MoveValue, MoveStruct},
    identifier::Identifier,
    language_storage::ModuleId,
};
#[cfg(feature = "aptos")]
use move_binary_format::{CompiledModule, access::ModuleAccess};
#[cfg(feature = "aptos")]
use std::collections::HashMap;
#[cfg(feature = "aptos")]
use crate::runner::aptos_helpers::registry::build_helpers;
#[cfg(feature = "aptos")]
use crate::runner::aptos_helpers::AptosHelper;
#[cfg(feature = "aptos")]
use aptos_cached_packages::aptos_stdlib::code_publish_package_txn;
#[cfg(feature = "aptos")]
use bcs;

use crate::runner::runner::{Runner, StatefulRunner};
use crate::{
    fuzzer::{coverage::Coverage, error::Error},
    mutator::types::Type as FuzzerType,
};

#[cfg(feature = "aptos")]
pub fn generate_inputs(inputs: Vec<FuzzerType>) -> Vec<MoveValue> {
    let mut res = vec![];
    for i in inputs {
        match i {
            FuzzerType::U8(value) => res.push(MoveValue::U8(value)),
            FuzzerType::U16(value) => res.push(MoveValue::U16(value)),
            FuzzerType::U32(value) => res.push(MoveValue::U32(value)),
            FuzzerType::U64(value) => res.push(MoveValue::U64(value)),
            FuzzerType::U128(value) => res.push(MoveValue::U128(value)),
            FuzzerType::Bool(value) => res.push(MoveValue::Bool(value)),
            FuzzerType::Vector(_, vec) => {
                res.push(MoveValue::Vector(generate_inputs(vec)))
            }
            FuzzerType::Struct(values) => res.push(MoveValue::Struct(
                MoveStruct::Runtime(generate_inputs(values)),
            )),
            FuzzerType::Reference(_, _) => {
                res.push(MoveValue::Address(AccountAddress::random()))
            }
            _ => unimplemented!(),
        }
    }
    res
}

#[cfg(feature = "aptos")]
pub struct AptosRunner {
    executor: FakeExecutor,
    account: Account,
    target_module: String,
    target_function: Option<FuzzerType>,
    modules: Vec<Vec<u8>>,
    package_metadata: Vec<u8>,
    package_address: AccountAddress,
    sequence_number: u64,
    aptos_helpers: HashMap<String, String>,
    helper_instances: HashMap<String, Box<dyn AptosHelper>>,
}

// Mark as Send - FakeExecutor is created and used within the same worker thread
#[cfg(feature = "aptos")]
unsafe impl Send for AptosRunner {}

#[cfg(feature = "aptos")]
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

#[cfg(feature = "aptos")]
impl AptosRunner {
    fn helper_for_function(&self, function_name: &str) -> Option<&dyn AptosHelper> {
        let key = format!("{}::{}", self.target_module, function_name);
        let helper_name = self.aptos_helpers.get(&key)?;
        self.helper_instances.get(helper_name).map(|h| h.as_ref())
    }

    pub fn new(
        target_module: &str,
        package_metadata: Vec<u8>,
        modules: Vec<Vec<u8>>,
        seed: u64,
        aptos_helpers: HashMap<String, String>,
    ) -> Self {
        // Create executor with genesis state (includes framework modules, chain config, etc.)
        let executor = FakeExecutor::from_head_genesis();

        let helper_instances = build_helpers(&aptos_helpers, seed);

        let mut runner = Self {
            executor,
            account: Account::new(), // placeholder, will be set in setup
            target_module: target_module.to_string(),
            target_function: None,
            modules,
            package_metadata,
            package_address: AccountAddress::from_hex_literal("0x1").unwrap(),
            sequence_number: 0,
            aptos_helpers,
            helper_instances,
        };

        runner.setup();
        runner
    }

    fn convert_move_value_to_aptos_arg(&self, value: &MoveValue) -> Option<TransactionArgument> {
        match value {
            MoveValue::Bool(v) => Some(TransactionArgument::Bool(*v)),
            MoveValue::U8(v) => Some(TransactionArgument::U8(*v)),
            MoveValue::U16(v) => Some(TransactionArgument::U16(*v)),
            MoveValue::U32(v) => Some(TransactionArgument::U32(*v)),
            MoveValue::U64(v) => Some(TransactionArgument::U64(*v)),
            MoveValue::U128(v) => Some(TransactionArgument::U128(*v)),
            MoveValue::Address(addr) => Some(TransactionArgument::Address(*addr)),
            MoveValue::Vector(vec) => {
                if let Some(MoveValue::U8(_)) = vec.first() {
                    let bytes: Vec<u8> = vec.iter()
                        .filter_map(|v| if let MoveValue::U8(b) = v { Some(*b) } else { None })
                        .collect();
                    Some(TransactionArgument::U8Vector(bytes))
                } else {
                    None
                }
            },
            _ => None,
        }
    }

    fn send_transaction(
        &mut self,
        target_function: &str,
        args: Vec<TransactionArgument>,
    ) -> Result<(TransactionStatus, u64), Error> {
        let module_id = ModuleId::new(
            self.package_address,
            Identifier::new(self.target_module.as_str()).map_err(|e| Error::Unknown {
                message: format!("Invalid module name: {}", e),
            })?,
        );

        let function_id = Identifier::new(target_function).map_err(|e| Error::Unknown {
            message: format!("Invalid function name: {}", e),
        })?;

        // Convert TransactionArguments to bytes for EntryFunction
        let args_bytes: Vec<Vec<u8>> = args.into_iter().map(|arg| {
            match arg {
                TransactionArgument::U8(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::U16(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::U32(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::U64(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::U128(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::U256(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::Bool(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::Address(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::U8Vector(v) => bcs::to_bytes(&v).unwrap(),
                TransactionArgument::Serialized(v) => v,
            }
        }).collect();

        let entry_function = EntryFunction::new(module_id, function_id, vec![], args_bytes);
        let payload = TransactionPayload::EntryFunction(entry_function);

        // Create and sign transaction using FakeExecutor's account helper
        let txn = self.account
            .transaction()
            .payload(payload)
            .sequence_number(self.sequence_number)
            .sign();

        // Execute transaction
        let output = self.executor.execute_transaction(txn);

        // Apply write set to maintain state
        self.executor.apply_write_set(output.write_set());

        // Increment sequence number for next transaction
        self.sequence_number += 1;

        let gas_used = output.gas_used();
        Ok((output.status().clone(), gas_used))
    }

    fn initialize_helper(&mut self, args: Vec<Vec<u8>>) -> Result<(TransactionStatus, u64), Error> {
        let args = args.into_iter().map(TransactionArgument::Serialized).collect();
        self.send_transaction("initialize", args)
    }

    fn publish_modules(&mut self) -> Result<TransactionOutput, Error> {
        let payload = code_publish_package_txn(self.package_metadata.clone(), self.modules.clone());

        // Create and sign publish transaction
        let txn = self.account
            .transaction()
            .payload(payload)
            .sequence_number(self.sequence_number)
            .sign();

        // Execute publish transaction
        let output = self.executor.execute_transaction(txn);

        // Check if publish succeeded
        match output.status() {
            TransactionStatus::Keep(ExecutionStatus::Success) => {
                // Apply write set to commit the published modules
                self.executor.apply_write_set(output.write_set());
                self.sequence_number += 1;
                Ok(output)
            },
            TransactionStatus::Keep(status) => {
                Err(Error::Unknown {
                    message: format!("Publish failed with status: {:?}", status),
                })
            },
            TransactionStatus::Discard(status) => {
                Err(Error::Unknown {
                    message: format!("Publish discarded: {:?}", status),
                })
            },
            TransactionStatus::Retry => {
                Err(Error::Unknown {
                    message: "Publish needs retry".to_string(),
                })
            },
        }
    }
}

#[cfg(feature = "aptos")]
impl Runner for AptosRunner {
    fn execute(
        &mut self,
        inputs: Vec<FuzzerType>,
    ) -> Result<(Option<Coverage>, u64), (Option<Coverage>, Error)> {
        let mut args = vec![];
        let function_name = match &self.target_function {
            Some(FuzzerType::Function(name, _, _)) => name.clone(),
            _ => {
                return Err((
                    None,
                    Error::Unknown {
                        message: "Invalid target function".to_string(),
                    },
                ))
            }
        };

        let adjusted_inputs = if let Some(helper) = self.helper_for_function(&function_name) {
            helper.transform_inputs(&inputs).unwrap_or_else(|| inputs.clone())
        } else {
            inputs.clone()
        };

        // Convert fuzzer inputs to transaction arguments
        for input in &generate_inputs(adjusted_inputs) {
            if let Some(arg) = self.convert_move_value_to_aptos_arg(input) {
                args.push(arg);
            }
        }

        let response = self.send_transaction(&function_name, args);

        match response {
            Ok((status, gas_used)) => {
                match status {
                    TransactionStatus::Keep(_) => {
                        // Successful execution
                        Ok((None, gas_used))
                    },
                    TransactionStatus::Discard(_) => Err((
                        None,
                        Error::Unknown {
                            message: "Transaction was discarded".to_string(),
                        },
                    )),
                    TransactionStatus::Retry => Err((
                        None,
                        Error::Unknown {
                            message: "Transaction should be retried".to_string(),
                        },
                    )),
                }
            },
            Err(err) => Err((None, err)),
        }
    }

    fn get_target_parameters(&self) -> Vec<FuzzerType> {
        self.target_function
            .clone()
            .unwrap()
            .as_function()
            .unwrap()
            .1
            .clone()
    }

    fn get_target_module(&self) -> String {
        self.target_module.clone()
    }

    fn get_target_function(&self) -> FuzzerType {
        self.target_function.clone().unwrap()
    }

    fn get_max_coverage(&self) -> usize {
        100 // Placeholder, gas meter is used instead
    }

    fn set_target_function(&mut self, function: &FuzzerType) {
        self.target_function = Some(function.clone());
    }
}

#[cfg(feature = "aptos")]
impl StatefulRunner for AptosRunner {
    fn setup(&mut self) {
        let package_address = resolve_package_address(&self.modules, &self.target_module);
        self.account = if let Some(addr) = package_address {
            self.executor.new_account_at(addr)
        } else {
            self.executor
                .create_accounts(1, 1_000_000_000_000_000, 0)
                .remove(0)
        };

        // Update package_address to the account's address (modules will be published here)
        self.package_address = *self.account.address();

        // Publish the fuzzing Move package
        if !self.modules.is_empty() {
            self.publish_modules().expect("Failed to publish modules");
        }

        let admin_addr = *self.account.address();
        let init_args: Vec<Vec<Vec<u8>>> = self
            .helper_instances
            .values()
            .filter_map(|helper| helper.initialize_args(admin_addr))
            .collect();
        for args in init_args {
            let _ = self.initialize_helper(args);
        }

        // Run fuzz_init entry function if present in the module
        let _ = self.send_transaction("fuzz_init", vec![]);
    }
}

// Stub implementation when aptos feature is not enabled
#[cfg(not(feature = "aptos"))]
pub struct AptosRunner {
    target_module: String,
    target_function: Option<FuzzerType>,
    modules: Vec<Vec<u8>>,
}

#[cfg(not(feature = "aptos"))]
impl AptosRunner {
    pub fn new(_target_module: &str, _modules: Vec<Vec<u8>>) -> Self {
        panic!("Aptos support not compiled. Please enable the 'aptos' feature.");
    }
}

#[cfg(not(feature = "aptos"))]
impl Runner for AptosRunner {
    fn execute(
        &mut self,
        _inputs: Vec<FuzzerType>,
    ) -> Result<(Option<Coverage>, u64), (Option<Coverage>, Error)> {
        unreachable!("Aptos support not compiled");
    }

    fn get_target_parameters(&self) -> Vec<FuzzerType> {
        unreachable!("Aptos support not compiled");
    }

    fn get_target_module(&self) -> String {
        unreachable!("Aptos support not compiled");
    }

    fn get_target_function(&self) -> FuzzerType {
        unreachable!("Aptos support not compiled");
    }

    fn get_max_coverage(&self) -> usize {
        unreachable!("Aptos support not compiled");
    }

    fn set_target_function(&mut self, _function: &FuzzerType) {
        unreachable!("Aptos support not compiled");
    }
}

#[cfg(not(feature = "aptos"))]
impl StatefulRunner for AptosRunner {
    fn setup(&mut self) {
        unreachable!("Aptos support not compiled");
    }
}
