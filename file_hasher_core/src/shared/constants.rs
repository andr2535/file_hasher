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

pub const HASH_OUTPUT_LENGTH:   usize = 32;
pub const FIN_CHECKSUM_PREFIX:  &str  = "CHECKSUM = ";
pub const XOR_CHECKSUM_PREFIX:  &str  = "XORCHECKSUM = ";

pub const LIST_VERSION_PREFIX:  &str  = "LISTVERSION = ";
pub const CURRENT_LIST_VERSION: &str  = "1.1";