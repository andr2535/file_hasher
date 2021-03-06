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

use crate::UserInterface;

use super::constants::HASH_OUTPUT_LENGTH;
use self::blake2::{VarBlake2b, digest::VariableOutput};
use super::Checksum;

/// Converts a VarBlake2b object into an Option of a HASH_OUTPUT_LENGTH 
/// length binary array.
/// 
/// Returns None if given "hasher" is not initialized with a length
/// of HASH_OUTPUT_LENGTH.
pub fn blake2_to_checksum(hasher: VarBlake2b) -> Option<Checksum> {
	let mut element_hash = None;
	hasher.finalize_variable(|res| {
		if res.len() == HASH_OUTPUT_LENGTH {
			element_hash = Some(Checksum::default()).map(|mut checksum| {
				checksum.iter_mut().zip(res).for_each(|(dest, src)| *dest = *src);
				checksum
			});
		}
	});
	element_hash
}

/// Converts a Blake2b object into a string.
/// The hash is output in capital hexadecimal letters.
/// 
/// Panics if "hasher" is not initialized with a length of HASH_OUTPUT_LENGTH
pub fn blake2_to_string(hasher: VarBlake2b) -> String {
	let hash = blake2_to_checksum(hasher).unwrap();
	hex::encode_upper(hash.as_ref())
}


pub fn get_with_ending_slash(user_interface: &impl UserInterface, question: &str) -> String {
	loop {
		let path = user_interface.get_user_answer(question);
		// We should only accept a relative path that ends in a forward slash.
		if let Some('/') = path.chars().rev().next() {
			break path;
		}
		else {
			user_interface.send_message("The path must end with a forward slash \"/\"");
		}
	}
}