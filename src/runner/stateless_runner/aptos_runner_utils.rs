use move_core_types::value::{MoveValue, MoveStruct};
use move_core_types::account_address::AccountAddress;
use aptos_types::transaction::TransactionArgument;
use crate::mutator::types::Type as FuzzerType;

/// Convert Move model type to fuzzer type
pub fn convert_move_type_to_fuzzer_type(move_type: &move_model::ty::Type) -> FuzzerType {
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

fn is_signer_param(move_type: &move_model::ty::Type) -> bool {
    use move_model::ty::{PrimitiveType, Type as MoveType};
    match move_type {
        MoveType::Primitive(PrimitiveType::Signer) => true,
        MoveType::Reference(_, inner) => is_signer_param(inner),
        _ => false,
    }
}

/// Generate ABI (function parameters and max coverage) from source
pub fn generate_abi_from_source(
    contract_path: &str,
    target_module: &str,
    target_function: &str
) -> (Vec<FuzzerType>, usize) {
    use move_package::{BuildConfig, ModelConfig};
    use move_package::compilation::model_builder::ModelBuilder;
    use move_model::metadata::{CompilerVersion, LanguageVersion};
    use std::path::Path;

    // Use Move 2.1 to support l1-migration framework features like += and -=
    let mut build_config = BuildConfig {
        test_mode: true,
        ..Default::default()
    };
    build_config.compiler_config.compiler_version = Some(CompilerVersion::V2_1);
    build_config.compiler_config.language_version = Some(LanguageVersion::V2_1);

    let resolution_graph = build_config
        .resolution_graph_for_package(Path::new(contract_path), &mut std::io::stderr())
        .unwrap();

    let source_env = ModelBuilder::create(
        resolution_graph,
        ModelConfig {
            all_files_as_targets: false,
            target_filter: None,
            compiler_version: CompilerVersion::V2_1,
            language_version: LanguageVersion::V2_1
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
            let max_coverage = f.get_bytecode().map(|bc| bc.len()).unwrap_or(0);
            let params = f
                .get_parameters()
                .iter()
                .filter(|p| !is_signer_param(&p.1))
                .map(|p| convert_move_type_to_fuzzer_type(&p.1))
                .collect();
            (params, max_coverage)
        } else {
            panic!("Could not find target function: {}", target_function);
        }
    } else {
        panic!("Could not find target module: {}", target_module);
    };

    (params, max_coverage)
}

/// Convert fuzzer types to MoveValues
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

/// Convert MoveValue to Aptos TransactionArgument
pub fn convert_move_value_to_aptos_arg(value: &MoveValue) -> Option<TransactionArgument> {
    match value {
        MoveValue::Bool(v) => Some(TransactionArgument::Bool(*v)),
        MoveValue::U8(v) => Some(TransactionArgument::U8(*v)),
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
