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

use self::blake2::{digest::VariableOutput, VarBlake2b};
use super::{constants::HASH_OUTPUT_LENGTH, Checksum};

/// Converts a VarBlake2b object into an Option of a HASH_OUTPUT_LENGTH
/// length binary array.
///
/// Panics if "hasher" is not initialized with a length of HASH_OUTPUT_LENGTH
pub fn blake2_to_checksum(hasher: VarBlake2b) -> Checksum {
	let mut element_hash = None;
	hasher.finalize_variable(|res| {
		if res.len() == HASH_OUTPUT_LENGTH {
			element_hash = Some(Checksum::default()).map(|mut checksum| {
				checksum.iter_mut().zip(res).for_each(|(dest, src)| *dest = *src);
				checksum
			});
		}
	});
	element_hash.unwrap()
}
