/*
	This file is part of file_hasher.

	file_hasher is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	file_hasher is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with file_hasher.  If not, see <https://www.gnu.org/licenses/>.
*/

extern crate blake2;

use super::constants;
use self::blake2::{Blake2b, digest::VariableOutput};

/// Converts a Blake2b object into a string.
/// The hash is output in capital hexadecimal letters.
pub fn blake2_to_string(hasher:Blake2b) -> String {
	let mut hash = [0u8; constants::HASH_OUTPUT_LENGTH];
	hasher.variable_result(&mut hash).unwrap();
	hash_to_string(&hash)
}

pub fn hash_to_string(hash: &[u8; constants::HASH_OUTPUT_LENGTH]) -> String {
	let mut hash_string = String::with_capacity(constants::HASH_OUTPUT_LENGTH*2);
	for byte in hash.iter() {
		hash_string.push_str(&format!("{:02X}", byte));
	}
	hash_string
}