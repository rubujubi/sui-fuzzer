#[cfg(feature = "aptos")]
pub mod registry;
#[cfg(feature = "aptos")]
pub mod usdcx_mint_helper;

use crate::mutator::types::Type as FuzzerType;
use move_core_types::account_address::AccountAddress;

pub trait AptosHelper {
    fn initialize_args(&self, _admin: AccountAddress) -> Option<Vec<Vec<u8>>> {
        None
    }

    fn transform_inputs(&self, _inputs: &[FuzzerType]) -> Option<Vec<FuzzerType>> {
        None
    }
}
