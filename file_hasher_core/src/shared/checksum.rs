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

use super::constants::HASH_OUTPUT_LENGTH;
use std::ops::{BitXorAssign, Deref, DerefMut};

type ChecksumArray = [u8; HASH_OUTPUT_LENGTH];
/// Checksum defines the standard length of any checksums
/// used in file_hasher_core.
///
/// Also defines a set of traits for better ergonomics.
#[derive(Debug, Eq, PartialEq, std::hash::Hash, Copy, Clone, Default)]
pub struct Checksum {
	checksum: ChecksumArray
}

impl BitXorAssign<&Checksum> for Checksum {
	fn bitxor_assign(&mut self, other: &Checksum) {
		self.checksum.iter_mut().zip(other.checksum.iter()).for_each(|(dest, other)| *dest ^= other);
	}
}

impl Deref for Checksum {
	type Target = ChecksumArray;

	fn deref(&self) -> &ChecksumArray {
		&self.checksum
	}
}

impl DerefMut for Checksum {
	fn deref_mut(&mut self) -> &mut ChecksumArray {
		&mut self.checksum
	}
	
}

impl AsRef<ChecksumArray> for Checksum {
	fn as_ref(&self) -> &ChecksumArray {
		self
	}
}