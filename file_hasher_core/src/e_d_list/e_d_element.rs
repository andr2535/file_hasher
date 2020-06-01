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
use blake2::{VarBlake2b, digest::{Input, VariableOutput}};

use crate::shared::constants::HASH_OUTPUT_LENGTH;
use crate::{shared, shared::Checksum};
use hex::decode_to_slice;

/// FileElement is a struct that contains the fields that
/// a file needs, but a symbolic link does not need.
#[derive(Debug)]
pub struct FileElement {
	pub file_checksum: Checksum
}

/// LinkElement is a struct that contains the fields, that
/// a symbolic link needs, that a file does not need.
#[derive(Debug)]
pub struct LinkElement {
	pub link_target: String
}

/// EDVariantFields is used to manage whether we are storing
/// a file or a symbolic link.
#[derive(Debug)]
pub enum EDVariantFields {
	File(FileElement),
	Link(LinkElement)
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
#[derive(Debug)]
pub struct EDElement {
	path: String,
	modified_time: u64,
	variant_fields: EDVariantFields,
	element_hash: Checksum
}
impl EDElement {
	/// from_internal creates an EDElement from the given arguments
	/// while also creating the element_hash for the EDElement.
	fn from_internal(path: String, modified_time: u64, variant_fields: EDVariantFields) -> EDElement {
		let mut hasher = VarBlake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		hasher.input(path.as_bytes());
		hasher.input(&modified_time.to_le_bytes());
		match &variant_fields {
			EDVariantFields::File(file) => hasher.input(*file.file_checksum),
			EDVariantFields::Link(link) => hasher.input(link.link_target.as_bytes())
		}
		let element_hash = shared::blake2_to_checksum(hasher).unwrap();
		EDElement{path, modified_time, variant_fields, element_hash}
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
	pub fn from_path(path: String) -> Result<EDElement, String> {
		let metadata = match fs::symlink_metadata(&path) {
			Ok(metadata) => metadata,
			Err(err) => return Err(format!("Error getting metadata of path \"{}\", error = {}", path, err))
		};
		
		let modified_time = metadata.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
		
		if metadata.is_file() {
			// The path is a file.
			let file = match File::open(&path) {
				Ok(file) => file,
				Err(err) => return Err(format!("Error opening path \"{}\", error = {}", path, err))
			};
			let hash = match EDElement::hash_file(file) {
				Ok(hash) => hash,
				Err(err) => return Err(format!("Error reading file {}, error = {}", path, err))
			};
			let file_fields = EDVariantFields::File(FileElement{file_checksum: hash});
			Ok(EDElement::from_internal(path, modified_time, file_fields))
		}
		else {
			// The path is a symbolic link
			match fs::read_link(&path).unwrap().to_str() {
				Some(link_path) =>  {
					// Verify that the link path exists.
					EDElement::verify_link_path(&path, &link_path)?;
					let link_fields = EDVariantFields::Link(LinkElement{link_target: link_path.to_string()});
					Ok(EDElement::from_internal(path, modified_time, link_fields))
				},
				None => Err(format!("link_path is not a valid utf-8 string!, path to link = {}", path))
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
	pub fn test_metadata(&self) -> Result<(), String> {
		let metadata = match fs::symlink_metadata(&self.path) {
			Ok(metadata) => metadata,
			Err(_err) => return Err(format!("Could not open path \"{}\"", self.path))
		};
		if metadata.is_dir() {return Err(format!("Path \"{}\" is a directory", self.path))}
		let modified_time = metadata.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
		if modified_time != self.modified_time {
			Err(format!("File with path \"{}\", has a different modified time than expected", self.path))
		}
		else {Ok(())}
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
	pub fn test_integrity(&self) -> Result<(), String> {
		let metadata = match fs::symlink_metadata(&self.path) {
			Ok(metadata) => metadata,
			Err(err) => return Err(format!("Error reading metadata from file {}, err = {}", self.path, err))
		};
		if metadata.is_dir() {return Err(format!("Path {} is a directory, directories cannot be a EDElement!", self.path));}
		
		let time_changed = {
			let modified_time = metadata.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
			modified_time != self.modified_time
		};
		
		match &self.variant_fields {
			EDVariantFields::File(file_element) => {
				let file = match File::open(&self.path) {
					Ok(file) => file,
					Err(err) => return Err(format!("Error opening file {} for testing, err = {}", self.path, err))
				};
				let file_hash = match EDElement::hash_file(file) {
					Ok(file_hash) => file_hash,
					Err(err) => return Err(format!("Error trying to read file {}, err = {}", self.path, err))
				};
				if file_hash == file_element.file_checksum {
					if time_changed {
						Err(format!("File \"{}\" has a valid checksum, but the time has been changed", self.path))
					}
					else {
						Ok(())
					}
				}
				else if time_changed {
					Err(format!("File \"{}\" has an invalid checksum, and it's time has been changed", self.path))
				}
				else {
					Err(format!("File \"{}\" has an invalid checksum", self.path))
				}
			},
			EDVariantFields::Link(link_element) => {
				let link_target = match fs::read_link(&self.path).unwrap().to_str() {
					Some(link_target) => link_target.to_string(),
					None => return Err(format!("link_target is not a valid utf-8 string!, path to link = {}", self.path))
				};
				if link_target == link_element.link_target {
					if time_changed {
						Err(format!("Time changed on link \"{}\", but link has valid target path", self.path))
					}
					else {
						// Verify that the link target exists.
						EDElement::verify_link_path(&self.path, &link_target)
					}
				}
				else if time_changed {
					Err(format!("Link \"{}\", has an invalid target path, and it's modified time has changed", self.path))
				}
				else {
					Err(format!("Link \"{}\", has an invalid target path", self.path))
				}
			}
		}
	}
	
	fn verify_link_path(path: &str, link_target: &str) -> Result<(), String> {
		use std::path::Path;
		let current_path = {
			match Path::new(path).parent() {
				Some(path) => path,
				None => return Err(format!("Link with path '{}', has link_target: '{}', which doesn't have a parent!", path, link_target))
			}
		};
		let real_link_target = current_path.join(link_target);
		match File::open(&real_link_target) {
			// If case Ok, we have verified that the link is valid.
			Ok(_linked_to_file) => Ok(()),
			Err(err) => Err(format!("Error opening file linked to by: '{}', link_target: '{}', error: '{}'", path, link_target, err))
		}
	}
	/// hash_file reads a file, and creates a hash for it in an
	/// u8 vector, of length HASH_OUTPUT_LENGTH.
	/// If there is trouble reading the file, we will return
	/// the error given.
	fn hash_file(mut file:File) -> Result<Checksum, std::io::Error> {
		let buffer_size = 40 * 1024 * 1024; // Buffer_size = 40MB
		let mut buffer = vec![0u8; buffer_size];
		let mut hasher = VarBlake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		loop {
			let result_size = file.read(&mut buffer)?;
			hasher.input(&buffer[0..result_size]);
			if result_size != buffer_size {break;}
		}
		Ok(shared::blake2_to_checksum(hasher).unwrap())
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
		std::mem::replace(&mut self.path, String::new())
	}

	pub fn get_modified_time(&self) -> u64 {
		self.modified_time
	}

	pub fn get_variant(&self) -> &EDVariantFields {
		&self.variant_fields
	}
}

impl std::convert::TryFrom<&str> for EDElement {
	type Error = String;
	
	/// Parses a string into an EDElement struct, if the string
	/// does not describe a valid EDElement struct, it will return
	/// a String containing an error message.
	fn try_from(value: &str) -> Result<EDElement, String> {
		let mut path = String::new();
		let mut char_iterator = value.chars();

		// Verifying that the first char is a [ character.
		match char_iterator.next() {Some('[') => (), _ => return Err("Missing start bracket".to_string())}
		
		// Parse the path of the EDElement.
		loop {
			match char_iterator.next() {
				Some('\\')      => {
					if let Some(escaped_char) = char_iterator.next() {
						path.push(escaped_char);
					}
					else {
						return Err("Missing escaped char in path".to_string());
					}
				},
				Some(',')       => break,
				Some(character) => path.push(character),
				None            => return Err("Missing end character after file name".to_string())
			}
		}

		// Parse modified time of the EDElement.
		let modified_time = {
			let mut time_string = String::new();
			loop {
				match char_iterator.next() {
					Some(',')        => break,
					Some(character)  => time_string.push(character),
					None             => return Err("Missing ending of modified time string".to_string())
				}
			}
			match u64::from_str_radix(&time_string, 10) {
				Ok(value) => value,
				Err(_err) => return Err("Error parsing modified time".to_string())
			}
		};
		
		// Parse the variant data of the EDElement.
		if char_iterator.as_str().len() < 5 {return Err("EDElement was missing information about its variant".to_string());};
		let variant_fields = match &char_iterator.as_str().as_bytes()[0..5] {
			b"file(" => {
				let mut file_checksum = Checksum::default();
				if char_iterator.as_str().len() < 5 + (HASH_OUTPUT_LENGTH * 2) {return Err("File hash is incomplete".to_string());}
				let result = decode_to_slice(&char_iterator.as_str().as_bytes()[5..5+HASH_OUTPUT_LENGTH * 2], &mut *file_checksum);
				if let Err(err) = result {return Err(format!("Error decoding file hash: {}", err));}
				char_iterator = char_iterator.as_str()[5 + HASH_OUTPUT_LENGTH * 2..].chars();

				match char_iterator.next() {Some(')') => (), _ => return Err("Missing end character after file_hash".to_string())}
				EDVariantFields::File(FileElement{file_checksum})
			},
			b"link(" => {
				char_iterator = char_iterator.as_str()[5..].chars();
				let mut link_target = String::new();
				loop {
					match char_iterator.next() {
						Some('\\')      => {
							if let Some(character) = char_iterator.next() {link_target.push(character);}
							else {return Err("Missing escaped character after '\\'".to_string())}
						},
						Some(')')       => break,
						Some(character) => link_target.push(character),
						None            => return Err("Missing end of link_target".to_string())
					}
				}
				EDVariantFields::Link(LinkElement{link_target})
			}
			_ => return Err("Invalid variant_string".to_string())
		};
		match char_iterator.next() {
			Some(']') => (),
			_ => return Err("Last bracket missing from EDElement string!".to_string())
		}
		Ok(EDElement::from_internal(path, modified_time, variant_fields))
	}
}

impl std::fmt::Display for EDElement {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let variant_fields = match &self.variant_fields {
			EDVariantFields::File(file) => format!("file({})", hex::encode_upper(*file.file_checksum)),
			EDVariantFields::Link(link) => format!("link({})", link.link_target.replace(r"\", r"\\").replace(")", r"\)"))
		};
		write!(f, "[{},{},{}]", self.path.replace(r"\", r"\\").replace(",", r"\,"), self.modified_time, variant_fields)
	}
}

impl AsRef<EDElement> for EDElement {
	#[inline]
	fn as_ref(&self) -> &EDElement {
		self
	}
}