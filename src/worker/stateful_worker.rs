use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
    time::Instant,
};

use bichannel::Channel;
#[cfg(feature = "sui")]
use move_model::ty::Type;
use move_model::metadata::{CompilerVersion, LanguageVersion};
use rand::{seq::SliceRandom, thread_rng};
use ark_std::iterable::Iterable;
use crate::{
    detector::detector::AvailableDetector,
    fuzzer::{coverage::Coverage, crash::Crash, stats::Stats},
    mutator::{mutator::Mutator, rng::Rng, types::Type as FuzzerType},
    runner::runner::StatefulRunner,
    worker::worker::WorkerEvent,
};

#[cfg(feature = "sui")]
use crate::runner::stateless_runner::sui_runner_utils::{
    generate_abi_from_source, generate_abi_from_source_starts_with,
};

use super::worker::Worker;

#[cfg(feature = "aptos")]
fn convert_move_type_to_fuzzer_type(move_type: &move_model::ty::Type) -> crate::mutator::types::Type {
    use crate::mutator::types::Type as FuzzerType;
    use move_model::ty::{PrimitiveType, Type as MoveType};
    match move_type {
        MoveType::Primitive(prim) => match prim {
            PrimitiveType::U8 => FuzzerType::U8(0),
            PrimitiveType::U16 => FuzzerType::U16(0),
            PrimitiveType::U32 => FuzzerType::U32(0),
            PrimitiveType::U64 => FuzzerType::U64(0),
            PrimitiveType::U128 => FuzzerType::U128(0),
            PrimitiveType::Bool => FuzzerType::Bool(false),
            PrimitiveType::Address => FuzzerType::Address([0; 32]),
            PrimitiveType::Signer => FuzzerType::Address([0; 32]),
            _ => FuzzerType::U64(0), // Default fallback
        },
        MoveType::Vector(inner) => {
            let inner_type = convert_move_type_to_fuzzer_type(inner);
            FuzzerType::Vector(Box::new(inner_type.clone()), vec![inner_type])
        },
        MoveType::Struct(_, _, _) => {
            // For structs, create a basic struct with one field
            FuzzerType::Struct(vec![FuzzerType::U64(0)])
        },
        MoveType::Reference(_, inner) => {
            // For references, convert the inner type and make it a reference
            let inner_type = convert_move_type_to_fuzzer_type(inner);
            FuzzerType::Reference(false, Box::new(inner_type))
        },
        _ => {
            // For any other types, default to U64
            FuzzerType::U64(0)
        }
    }
}

#[cfg(feature = "aptos")]
fn is_signer_param(move_type: &move_model::ty::Type) -> bool {
    use move_model::ty::{PrimitiveType, Type as MoveType};
    match move_type {
        MoveType::Primitive(PrimitiveType::Signer) => true,
        MoveType::Reference(_, inner) => is_signer_param(inner),
        _ => false,
    }
}

#[cfg(feature = "aptos")]
fn generate_abi_from_source(
    contract: &str,
    target_module: &str,
    target_function: &str
) -> (Vec<crate::mutator::types::Type>, usize) {
    use move_package::{BuildConfig, ModelConfig};
    use move_package::compilation::model_builder::ModelBuilder;
    use std::path::Path;

    let build_config = BuildConfig {
        test_mode: true,
        ..Default::default()
    };

    let resolution_graph = build_config
        .resolution_graph_for_package(Path::new(contract), &mut std::io::stderr())
        .unwrap();

    #[cfg(feature="sui")]
    let source_env = ModelBuilder::create(
        resolution_graph,
        ModelConfig {
            all_files_as_targets: false,
            target_filter: None,
        },
    )
    .build_model()
    .unwrap();

    #[cfg(feature="aptos")]
    let source_env = ModelBuilder::create(
        resolution_graph,
        ModelConfig {
            all_files_as_targets: false,
            target_filter: None,
            compiler_version: CompilerVersion::default(),
            language_version: LanguageVersion::default()
        },
    )
    .build_model()
    .unwrap();

    let module_env = source_env
        .get_modules()
        .find(|m| m.matches_name(target_module));

    let (params, max_coverage) = if let Some(env) = module_env {
        let func = env
            .get_functions()
            .find(|f| f.get_name_str() == target_function);
        if let Some(f) = func {

            let max_coverage = f.get_bytecode().len();
            let params = f
                .get_parameters()
                .iter()
                .filter(|p| !is_signer_param(&p.1))
                .map(|p| convert_move_type_to_fuzzer_type(&p.1))
                .collect();
            (params, max_coverage)
        } else {
            panic!("Could not find target function !");
        }
    } else {
        panic!("Could not find target module {} !", target_module);
    };

    (params, max_coverage)
}


#[cfg(feature = "aptos")]
fn generate_abi_from_source_starts_with(
    contract: &str,
    target_module: &str,
    prefix: &str
) -> Vec<(String, Vec<crate::mutator::types::Type>, Vec<crate::mutator::types::Type>)> {
    use move_package::{BuildConfig, ModelConfig};
    use move_package::compilation::model_builder::ModelBuilder;
    use std::path::Path;

    let build_config = BuildConfig {
        test_mode: true,
        ..Default::default()
    };

    let resolution_graph = build_config
        .resolution_graph_for_package(Path::new(contract), &mut std::io::stderr())
        .unwrap();

    let source_env = ModelBuilder::create(
        resolution_graph,
        ModelConfig {
            all_files_as_targets: false,
            target_filter: None,
            compiler_version: CompilerVersion::default(),
            language_version: LanguageVersion::default()
        },
    )
    .build_model()
    .unwrap();

    let module_env = source_env
        .get_modules()
        .find(|m| m.matches_name(target_module))
        .unwrap_or_else(|| panic!("Could not find target module {}", target_module));

    let mut functions = Vec::new();
    for func_env in module_env.get_functions() {
        if func_env.get_name_str().starts_with(prefix) {
            let params: Vec<crate::mutator::types::Type> = func_env
                .get_parameters()
                .iter()
                .map(|p| convert_move_type_to_fuzzer_type(&p.1))
                .collect();

            // Extract actual return types from function signature
            #[cfg(feature="sui")]
            let return_types: Vec<crate::mutator::types::Type> = func_env
                .get_return_types()
                .iter()
                .map(|return_type| convert_move_type_to_fuzzer_type(return_type))
                .collect();
            #[cfg(feature="aptos")]
            let return_types: Vec<crate::mutator::types::Type> = vec![
    convert_move_type_to_fuzzer_type(&func_env.get_result_type())
];



            functions.push((
                func_env.get_name_str().to_string(),
                params,
                return_types,
            ));
        }
    }

    functions
}

#[allow(dead_code)]
const STATE_INIT_POSTFIX: &str = "init";

pub struct StatefulWorker {
    channel: Channel<WorkerEvent, WorkerEvent>,
    stats: Arc<RwLock<Stats>>,
    runner: Box<dyn StatefulRunner>,
    mutator: Box<dyn Mutator>,
    rng: Rng,
    unique_crashes_set: HashSet<Crash>,
    target_functions: Vec<FuzzerType>,
    fuzz_functions: Vec<FuzzerType>,
    max_call_sequence_size: u32,
}

impl StatefulWorker {
    pub fn new(
        contract: &str,
        channel: Channel<WorkerEvent, WorkerEvent>,
        stats: Arc<RwLock<Stats>>,
        _coverage_set: HashSet<Coverage>,
        runner: Box<dyn StatefulRunner>,
        mutator: Box<dyn Mutator>,
        seed: u64,
        _execs_before_cov_update: u64,
        _available_detectors: Option<Vec<AvailableDetector>>,
        target_module: &str,
        target_functions: Vec<String>,
        fuzz_prefix: String,
        max_call_sequence_size: u32,
    ) -> Self {
        // Gets info on targeted functions
        let mut functions = vec![];
        for target_function in &target_functions {
            let (parameters, _) =
                generate_abi_from_source(contract, target_module, target_function);
            functions.push(FuzzerType::Function(
                target_function.clone(),
                Self::transform_params(parameters),
                None,
            ));
        }

        // Gets info on fuzz functions
        let mut fuzz_functions = vec![];
        let mut functions_abi =
            generate_abi_from_source_starts_with(contract, target_module, &fuzz_prefix);
        // Removes fuzz_init
        if let Some(pos) = functions_abi.iter().position(|f| f.0 == "fuzz_init") {
            functions_abi.remove(pos);
        }
        #[cfg(feature = "sui")]
        for (function_name, parameters) in functions_abi {
            fuzz_functions.push(FuzzerType::Function(
                function_name,
                Self::transform_params(parameters),
                None,
            ));
        }

        #[cfg(feature = "aptos")]
        for (function_name, parameters, _return_types) in functions_abi {
            fuzz_functions.push(FuzzerType::Function(
                function_name,
                Self::transform_params(parameters),
                None,
            ));
        }

        StatefulWorker {
            channel,
            stats,
            runner,
            mutator,
            rng: Rng {
                seed,
                exp_disabled: false,
            },
            target_functions: functions,
            fuzz_functions: fuzz_functions,
            unique_crashes_set: HashSet::new(),
            max_call_sequence_size,
        }
    }

    #[cfg(feature = "sui")]
    fn transform_params(params: Vec<Type>) -> Vec<FuzzerType> {
        let mut res = vec![];
        for param in params {
            res.push(FuzzerType::from(param));
        }
        res
    }

    #[cfg(feature = "aptos")]
    fn transform_params(params: Vec<crate::mutator::types::Type>) -> Vec<FuzzerType> {
        params
    }

    fn generate_call_sequence(&self, size: u32) -> Vec<FuzzerType> {
        let mut target_functions = self.target_functions.clone();
        let mut call_sequence: Vec<FuzzerType> =
            Vec::from_iter(self.fuzz_functions.iter().cloned());
        call_sequence.append(&mut target_functions);
        for _ in 0..size {
            let n = self
                .mutator
                .generate_number(0, (call_sequence.len() - 1).try_into().unwrap());
            call_sequence.push(call_sequence[n as usize].clone());
        }
        call_sequence.shuffle(&mut thread_rng());
        call_sequence
    }


}

impl Worker for StatefulWorker {
    fn run(&mut self) {
        // Utils for execs per sec
        let mut execs_per_sec_timer = Instant::now();
        let mut sec_elapsed = 0;

        loop {
            let call_sequence_size = self
                .rng
                .rand(1, self.max_call_sequence_size.try_into().unwrap())
                .try_into()
                .unwrap();
            let call_sequence = self.generate_call_sequence(call_sequence_size);

            // Call each function in the call sequence
            for function in call_sequence {
                // Reset function
                self.runner.set_target_function(&function);

                // Input initialization
                let mut inputs = function.as_function().unwrap().1.clone();

                // Mutate inputs with gas bias
                let current_gas = self.stats.read().unwrap().get_max_gas(&function);
                inputs = self.mutator.mutate_with_gas(&inputs, 4, Some(current_gas));

                //eprintln!("{} {:?}", function.as_function().unwrap().0, inputs);

                let exec_result = self.runner.execute(inputs.clone());

                self.stats.write().unwrap().execs += 1;

                // Calculate execs_per_sec
                if execs_per_sec_timer.elapsed().as_secs() >= 1 {
                    execs_per_sec_timer = Instant::now();
                    sec_elapsed += 1;
                    let tmp = self.stats.read().unwrap().execs;
                    self.stats.write().unwrap().secs_since_last_cov += 1;
                    self.stats.write().unwrap().execs_per_sec = tmp / sec_elapsed;
                }

                match exec_result {
                    Ok((_cov, gas_used)) => {
                        /*
                          Update gas usage when execution successes
                         */
                        self.stats.write().unwrap().update_gas_usage(&function, gas_used);
                    },
                    Err((_cov, error)) => {
                        self.stats.write().unwrap().crashes += 1;
                        let crash = Crash::new(
                            &self.runner.get_target_module(),
                            &self.runner.get_target_function().as_function().unwrap().0,
                            &inputs,
                            &error,
                        );
                        if !self.unique_crashes_set.contains(&crash) {
                            self.channel
                                .send(WorkerEvent::NewCrash(
                                    self.runner
                                        .get_target_function()
                                        .as_function()
                                        .unwrap()
                                        .0
                                        .to_string(),
                                    inputs.clone(),
                                    error,
                                ))
                                .unwrap();
                        }
                    }
                }
            }

            // Reset state
            self.runner.setup();
        }
    }
}
