#[allow(clippy::module_inception)]
pub mod keygen;

pub use keygen::{
    default_key_dir, default_key_dir_for, generate_ed25519_keypair, generate_or_load_key,
    generate_or_load_key_in, generate_zsync, parse_ed25519_armored_signature, run_keygen,
    run_keygen_with_key_dir, sign_bytes, validate_ed25519_signature, verify_signature,
    KeygenResults,
};
