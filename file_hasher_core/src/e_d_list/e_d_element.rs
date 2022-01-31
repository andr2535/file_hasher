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

use std::{fs, fs::File, io::prelude::Read, time::SystemTime};

use blake2::{
	digest::{Update, VariableOutput},
	Blake2bVar,
};
use hex::decode_to_slice;

use crate::{
	shared,
	shared::{constants::HASH_OUTPUT_LENGTH, Checksum},
};

pub mod errors;
use errors::*;

/// EDVariantFields is used to manage whether we are storing
/// a file or a symbolic link.
#[derive(Debug, PartialEq, Eq, std::hash::Hash, Clone)]
pub enum EDVariantFields {
	File { checksum: Checksum },
	Link { target: String },
}
impl EDVariantFields {
	pub fn is_link(&self) -> bool {
		if let EDVariantFields::Link { target: _ } = self { true } else { false }
	}
}

/// EDElement, a shorthand for Error-detect-element
/// It should be used by a EDList object, for safely storing
/// metadata about files and links.
///
/// path is used for storing the path for the element
///
/// modified_time is used for storing the exact time of the
/// last modification of the file or link.
///
/// variant_fields can store either information about a
/// file, or it can store information about a link.
///
/// element_hash contains a hash value of all the fields in
/// the EDElement object.
/// element_hash should never be identical between two different
/// EDElement objects, even if they have the same file_hash.
#[derive(Debug, Clone)]
pub struct EDElement {
	path:           String,
	modified_time:  u64,
	variant_fields: EDVariantFields,
	element_hash:   Checksum,
}
impl EDElement {
	/// from_internal creates an EDElement from the given arguments
	/// while also creating the element_hash for the EDElement.
	fn from_internal(path: String, modified_time: u64, variant_fields: EDVariantFields) -> EDElement {
		let mut new_element = EDElement { path, modified_time, variant_fields, element_hash: Checksum::default() };
		new_element.calculate_hash();
		new_element
	}

	fn calculate_hash(&mut self) {
		let mut hasher = Blake2bVar::new(HASH_OUTPUT_LENGTH).unwrap();
		hasher.update(self.path.as_bytes());
		hasher.update(&self.modified_time.to_le_bytes());
		match &self.variant_fields {
			EDVariantFields::File { checksum } => hasher.update(checksum.as_ref()),
			EDVariantFields::Link { target } => hasher.update(target.as_bytes()),
		}
		self.element_hash = shared::blake2_to_checksum(hasher);
	}

	/// from_path generates an EDElement from a path.
	/// It detects automatically whether the path
	/// refers to a link or a file.
	///
	/// Returns an error if the path refers to a directory.
	/// Or if in some other way processing of the file does
	/// not complete correctly.
	///
	/// Also returns an error if the path is a symbolic link
	/// and its link_path is not a valid utf-8 string.
	///
	/// Panics if one of these conditions are true:
	/// * The filesystem/OS doesn't support reading the link_path of a symbolic link.
	/// * The filesystem doesn't support reading the modified time of a file.
	/// * The argument "path" is neither a file nor a symbolic link.
	pub fn from_path(path: String) -> Result<EDElement, EDElementError> {
		let metadata = fs::symlink_metadata(&path).map_err(|err| EDElementError::GetMetaDataError(path.to_string(), err))?;
		let modified_time = metadata.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

		if metadata.is_file() {
			// The path is a file.
			let mut file = File::open(&path).map_err(|err| EDElementError::OpenFileError(path.to_string(), err))?;
			let checksum = EDElement::hash_file(&mut file).map_err(|err| EDElementError::FileHashingError(path.to_string(), err))?;
			let file_fields = EDVariantFields::File { checksum };
			Ok(EDElement::from_internal(path, modified_time, file_fields))
		}
		else {
			// The path is a symbolic link
			match fs::read_link(&path).unwrap().to_str() {
				Some(link_path) => {
					// Verify that the link path exists.
					EDElement::verify_link_path(&path, link_path)?;
					let link_fields = EDVariantFields::Link { target: link_path.to_string() };
					Ok(EDElement::from_internal(path, modified_time, link_fields))
				},
				None => Err(EDElementError::InvalidUtf8Link(path))?,
			}
		}
	}

	/// Does a cursory test for if the path has been deleted,
	/// or if the modified time of the path has been changed.
	///
	/// If the metadata does not match the stored metadata, a
	/// Err<String> is returned.
	///
	/// Panics if the filesystem/OS doesn't support reading
	/// the last modified time of a file, or interpreting
	/// it as time since epoch
	pub fn test_metadata(&self) -> Result<(), EDElementError> {
		let metadata = fs::symlink_metadata(&self.path).map_err(|err| EDElementError::GetMetaDataError(self.path.to_owned(), err))?;

		if metadata.is_dir() {
			Err(EDElementVerifyError::PathIsDirectory(self.path.to_owned()))?
		}
		let modified_time = metadata.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
		if modified_time != self.modified_time {
			Err(EDElementVerifyError::TimeChanged(self.path.to_owned()))?
		}
		else {
			Ok(())
		}
	}

	/// test_integrity tests the integrity of the EDElement against
	/// the file or symbolic link it points to.
	///
	/// If the symbolic_link or file has changed, or there has
	/// been corruption in the EDElement struct, an Err
	/// containing a string describing the error will be returned.
	/// If the integrity test went fine, it will return an Ok(()).
	///
	/// Panics if one of the following is true
	///
	/// The filesystem/OS doesn't support reading
	/// the last modified time of a file, or interpreting
	/// it as time since epoch.
	///
	/// The filesystem/OS doesn't support reading
	/// the link_path of a symbolic link
	pub fn test_integrity(&self) -> Result<(), EDElementError> {
		let metadata = fs::symlink_metadata(&self.path).map_err(|err| EDElementError::GetMetaDataError(self.path.to_owned(), err))?;

		let time_changed = {
			let modified_time = metadata.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
			modified_time != self.modified_time
		};

		match &self.variant_fields {
			EDVariantFields::File { checksum } => {
				let mut file = File::open(&self.path).map_err(|err| EDElementError::OpenFileError(self.path.to_owned(), err))?;
				let file_hash =
					EDElement::hash_file(&mut file).map_err(|err| EDElementError::FileHashingError(self.path.to_owned(), err))?;
				if file_hash == *checksum {
					if time_changed {
						Err(EDElementVerifyError::TimeChangedButFileCorrectError(self.path.to_owned()))?
					}
					else {
						Ok(())
					}
				}
				else if time_changed {
					Err(EDElementVerifyError::TimeChangedAndFileChanged(self.path.to_owned()))?
				}
				else {
					Err(EDElementVerifyError::InvalidChecksum(self.path.to_owned()))?
				}
			},
			EDVariantFields::Link { target } => {
				let link_target = match fs::read_link(&self.path).unwrap().to_str() {
					Some(link_target) => link_target.to_string(),
					None => Err(EDElementError::LinkTargetInvalidUtf8(self.path.to_owned()))?,
				};
				if link_target == *target {
					if time_changed {
						Err(EDElementVerifyError::LinkTargetValidTimeChanged(self.path.to_owned()))?
					}
					else {
						// Verify that the link target exists.
						EDElement::verify_link_path(&self.path, &link_target)?;
						Ok(())
					}
				}
				else if time_changed {
					Err(EDElementVerifyError::LinkTargetInvalidTimeChanged(self.path.to_owned()))?
				}
				else {
					Err(EDElementVerifyError::LinkTargetInvalid(self.path.to_owned()))?
				}
			},
		}
	}

	fn verify_link_path(path: &str, link_target: &str) -> Result<(), VerifyLinkPathError> {
		use std::path::Path;
		let current_path = {
			match Path::new(path).parent() {
				Some(path) => path,
				None => {
					return Err(VerifyLinkPathError::LinkFileNoParentError(path.to_owned(), link_target.to_owned()));
				},
			}
		};
		let real_link_target = current_path.join(link_target);
		match File::open(&real_link_target) {
			// If case Ok, we have verified that the link is valid.
			Ok(_linked_to_file) => Ok(()),
			Err(err) => Err(VerifyLinkPathError::UnableToOpenLinkTarget(path.to_owned(), link_target.to_owned(), err)),
		}
	}

	/// hash_file reads a file, and creates a hash for it in an
	/// u8 vector, of length HASH_OUTPUT_LENGTH.
	/// If there is trouble reading the file, we will return
	/// the error given.
	pub fn hash_file(file: &mut dyn Read) -> Result<Checksum, FileHashingError> {
		let buffer_size = 40 * 1024 * 1024; // Buffer_size = 40MB
		let mut buffer = vec![0u8; buffer_size];
		let mut hasher = Blake2bVar::new(HASH_OUTPUT_LENGTH).unwrap();
		loop {
			let result_size = file.read(&mut buffer)?;
			hasher.update(&buffer[0..result_size]);
			if result_size != buffer_size {
				break;
			}
		}
		Ok(shared::blake2_to_checksum(hasher))
	}

	/// Returns a hash of the entire EDElement.
	/// This hash does not represent the file_hash, it
	/// represents the entire EDElement.
	/// So if anything changes inside the EDElement,
	/// this hash would be invalid.
	pub fn get_hash(&self) -> &Checksum {
		&self.element_hash
	}

	/// Returns an immutable reference to the path
	/// of this EDElement.
	pub fn get_path(&self) -> &str {
		&self.path
	}

	/// Returns the path of this EDElement as an owned String.
	/// This will drop the EDElement in the process.
	pub fn take_path(mut self) -> String {
		std::mem::take(&mut self.path)
	}

	/// Override set path, only used for syncing two lists.
	pub fn update_path(&mut self, new_path: String) {
		self.path = new_path;
		self.calculate_hash();
	}

	pub fn get_modified_time(&self) -> u64 {
		self.modified_time
	}

	pub fn get_variant(&self) -> &EDVariantFields {
		&self.variant_fields
	}
}

impl std::convert::TryFrom<&str> for EDElement {
	type Error = EDElementParseError;

	/// Parses a string into an EDElement struct, if the string
	/// does not describe a valid EDElement struct, it will return
	/// a String containing an error message.
	fn try_from(value: &str) -> Result<EDElement, EDElementParseError> {
		let mut path = String::new();
		let mut char_iterator = value.chars();

		// Verifying that the first char is a [ character.
		match char_iterator.next() {
			Some('[') => (),
			_ => return Err(EDElementParseError::NoStartBracket),
		}

		// Parse the path of the EDElement.
		loop {
			match char_iterator.next() {
				Some('\\') => {
					if let Some(escaped_char) = char_iterator.next() {
						path.push(escaped_char);
					}
					else {
						return Err(EDElementParseError::EscapedCharacterMissing);
					}
				},
				Some(',') => break,
				Some(character) => path.push(character),
				None => return Err(EDElementParseError::NoFilePathTerminator),
			}
		}

		// Parse modified time of the EDElement.
		let modified_time = {
			let mut time_string = String::new();
			loop {
				match char_iterator.next() {
					Some(',') => break,
					Some(character) => time_string.push(character),
					None => return Err(EDElementParseError::NoModifiedTimeTerminator),
				}
			}
			time_string.parse::<u64>()?
		};

		// Parse the variant data of the EDElement.
		if char_iterator.as_str().len() < 5 {
			return Err(EDElementParseError::NoVariantInformation);
		};
		let variant_fields = match &char_iterator.as_str().as_bytes()[0..5] {
			b"file(" => {
				let mut file_checksum = Checksum::default();
				if char_iterator.as_str().len() < 5 + (HASH_OUTPUT_LENGTH * 2) {
					return Err(EDElementParseError::IncompleteFileHash);
				}
				decode_to_slice(&char_iterator.as_str().as_bytes()[5..5 + HASH_OUTPUT_LENGTH * 2], &mut *file_checksum)?;
				char_iterator = char_iterator.as_str()[5 + HASH_OUTPUT_LENGTH * 2..].chars();

				match char_iterator.next() {
					Some(')') => (),
					_ => return Err(EDElementParseError::NoVariantTerminator),
				}
				EDVariantFields::File { checksum: file_checksum }
			},
			b"link(" => {
				char_iterator = char_iterator.as_str()[5..].chars();
				let mut link_target = String::new();
				loop {
					match char_iterator.next() {
						Some('\\') => {
							if let Some(character) = char_iterator.next() {
								link_target.push(character);
							}
							else {
								return Err(EDElementParseError::EscapedCharacterMissing);
							}
						},
						Some(')') => break,
						Some(character) => link_target.push(character),
						None => return Err(EDElementParseError::NoVariantTerminator),
					}
				}
				EDVariantFields::Link { target: link_target }
			},
			_ => return Err(EDElementParseError::InvalidVariantIdentifier),
		};
		match char_iterator.next() {
			Some(']') => (),
			_ => return Err(EDElementParseError::NoTerminatorBracket),
		}
		Ok(EDElement::from_internal(path, modified_time, variant_fields))
	}
}
impl std::fmt::Display for EDElement {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let variant_fields = match &self.variant_fields {
			EDVariantFields::File { checksum } => format!("file({})", hex::encode_upper(checksum.as_ref())),
			EDVariantFields::Link { target } => format!("link({})", target.replace(r"\", r"\\").replace(")", r"\)")),
		};
		write!(
			f,
			"[{},{},{}]",
			self.path.replace(r"\", r"\\").replace(',', r"\,"),
			self.modified_time,
			variant_fields
		)
	}
}

impl AsRef<EDElement> for EDElement {
	#[inline]
	fn as_ref(&self) -> &EDElement {
		self
	}
}
