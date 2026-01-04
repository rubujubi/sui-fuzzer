use crate::mutator::types::Type as FuzzerType;
use crate::runner::aptos_helpers::AptosHelper;
use bcs;
use libsecp256k1::{Message, PublicKey, SecretKey, sign};
use move_core_types::account_address::AccountAddress;
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use tiny_keccak::{Hasher, Keccak};

pub struct UsdcxMintHelper {
    seed: u64,
    secp_secret: SecretKey,
    secp_pubkey: Vec<u8>,
    domain: u32,
}

impl UsdcxMintHelper {
    pub fn new(seed: u64) -> Self {
        let (secp_secret, secp_pubkey) = derive_secp256k1_key(seed);
        Self {
            seed,
            secp_secret,
            secp_pubkey,
            domain: 0,
        }
    }

    fn initialize_args_impl(&self, admin: AccountAddress) -> Vec<Vec<u8>> {
        vec![
            bcs::to_bytes(&self.domain).unwrap(),
            bcs::to_bytes(&b"USDCx".to_vec()).unwrap(),
            bcs::to_bytes(&b"USDCx".to_vec()).unwrap(),
            bcs::to_bytes(&6u8).unwrap(),
            bcs::to_bytes(&Vec::<u8>::new()).unwrap(),
            bcs::to_bytes(&Vec::<u8>::new()).unwrap(),
            bcs::to_bytes(&admin).unwrap(),
            bcs::to_bytes(&Vec::<AccountAddress>::new()).unwrap(),
            bcs::to_bytes(&vec![self.secp_pubkey.clone()]).unwrap(),
        ]
    }

    fn prepare_mint_inputs_impl(&self, inputs: &[FuzzerType]) -> Vec<FuzzerType> {
        let intent_entropy = inputs.get(0).map(u8_vec_from_fuzzer).unwrap_or_default();
        let hook_data = inputs.get(1).map(u8_vec_from_fuzzer).unwrap_or_default();
        let fee_input = match inputs.get(2) {
            Some(FuzzerType::U64(v)) => *v,
            _ => 0,
        };

        let mut rng = StdRng::seed_from_u64(mix_seed(self.seed, &intent_entropy));
        let magic = rng.next_u32();
        let version = 1u32;
        let amount = 1 + (rng.next_u64() % 1_000_000_000);
        let max_fee = amount;
        let fee_amount = fee_input.min(max_fee);
        let remote_domain = self.domain;

        let mut remote_token = [0u8; 32];
        let mut remote_recipient = [0u8; 32];
        let mut local_token = [0u8; 32];
        let mut local_depositor = [0u8; 32];
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut remote_token);
        rng.fill_bytes(&mut remote_recipient);
        rng.fill_bytes(&mut local_token);
        rng.fill_bytes(&mut local_depositor);
        rng.fill_bytes(&mut nonce);

        let hook_len = hook_data.len().min(32) as u32;

        let mut payload = Vec::new();
        payload.extend_from_slice(&magic.to_be_bytes());
        payload.extend_from_slice(&version.to_be_bytes());
        payload.extend_from_slice(&u64_to_u256_bytes(amount));
        payload.extend_from_slice(&remote_domain.to_be_bytes());
        payload.extend_from_slice(&remote_token);
        payload.extend_from_slice(&remote_recipient);
        payload.extend_from_slice(&local_token);
        payload.extend_from_slice(&local_depositor);
        payload.extend_from_slice(&u64_to_u256_bytes(max_fee));
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&hook_len.to_be_bytes());
        payload.extend_from_slice(&hook_data[..hook_len as usize]);

        let mut hasher = Keccak::v256();
        hasher.update(&payload);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        let msg = Message::parse_slice(&hash).expect("hash length");
        let (sig, recid) = sign(&msg, &self.secp_secret);
        let mut sig_bytes = sig.serialize().to_vec();
        sig_bytes.push(recid.serialize());

        vec![
            fuzzer_vec_from_u8(payload),
            fuzzer_vec_from_u8(sig_bytes),
            FuzzerType::U64(fee_amount),
        ]
    }
}

impl AptosHelper for UsdcxMintHelper {
    fn initialize_args(&self, admin: AccountAddress) -> Option<Vec<Vec<u8>>> {
        Some(self.initialize_args_impl(admin))
    }

    fn transform_inputs(&self, inputs: &[FuzzerType]) -> Option<Vec<FuzzerType>> {
        Some(self.prepare_mint_inputs_impl(inputs))
    }
}

fn derive_secp256k1_key(seed: u64) -> (SecretKey, Vec<u8>) {
    let mut rng = StdRng::seed_from_u64(seed);
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(secret) = SecretKey::parse_slice(&bytes) {
            let public = PublicKey::from_secret_key(&secret);
            let serialized = public.serialize();
            let raw = serialized[1..].to_vec();
            return (secret, raw);
        }
    }
}

fn mix_seed(base: u64, bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(base, |acc, b| acc.wrapping_mul(31).wrapping_add(*b as u64))
}

fn u8_vec_from_fuzzer(input: &FuzzerType) -> Vec<u8> {
    match input {
        FuzzerType::Vector(_, values) => values
            .iter()
            .filter_map(|v| match v {
                FuzzerType::U8(b) => Some(*b),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

fn fuzzer_vec_from_u8(bytes: Vec<u8>) -> FuzzerType {
    let values = bytes.into_iter().map(FuzzerType::U8).collect();
    FuzzerType::Vector(Box::new(FuzzerType::U8(0)), values)
}

fn u64_to_u256_bytes(value: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&value.to_be_bytes());
    buf
}
