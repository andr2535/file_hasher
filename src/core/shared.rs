extern crate blake2;

use super::constants;
use self::blake2::{Blake2b, digest::VariableOutput};

/// Converts a Blake2b object into a string.
/// The hash is output in capital hexadecimal letters.
pub fn blake2_to_string(hasher:Blake2b) -> String {
	let mut hash = [0u8; constants::HASH_OUTPUT_LENGTH];
	hasher.variable_result(&mut hash).unwrap();

	let mut hash_string = String::with_capacity(constants::HASH_OUTPUT_LENGTH*2);
	for byte in hash.iter() {
		hash_string.push_str(&format!("{:02X}", byte));
	}

	hash_string
}