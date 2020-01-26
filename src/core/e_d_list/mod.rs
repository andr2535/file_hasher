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

pub mod e_d_element;

use self::e_d_element::EDElement;
use super::shared;
use super::path_banlist::PathBanlist;
use crate::core::constants::*;

use chrono::prelude::{DateTime, Local};
use blake2::{Blake2b, digest::{Input, VariableOutput}};
use hex::decode_to_slice;
use std::{fs::{File, create_dir_all}, io::{BufRead, BufReader, Write}, collections::HashMap};
use crate::interfacer::UserInterface;

enum ListVersion<'a> {
	V1_0,
	V1_1,
	MissingIdentifier,
	InvalidVersion(&'a str)
}

enum LineType {
	FinChecksum(String),
	XorChecksum(String),
	EDElement
}

/// EDList is a list of all the files in a subdirectory
/// to the current directory, excepting the files that
/// lies under the paths that exists in the banlist.
///
/// The xor_checksum is calculated by xoring the element_hash
/// of the EDElement files together, it is used together
/// with the EDElements to create a checksum that is also saved
/// to the hashlist file.
///
/// The xor_checksum is the checksum of each EDElement object
/// xored together.
/// 
/// The checksum will always be checked against the
/// saved checksum in the file, when loading the list from
/// file. Also the saved checksum is used in the memory,
/// such that it is very hard for a memory error to cause
/// data corruption in the file after a reload.
#[derive(Debug)]
pub struct EDList {
	element_list: Vec<EDElement>,
	banlist: PathBanlist,
	xor_checksum: [u8; HASH_OUTPUT_LENGTH]
}
impl EDList {
	/// Attempts to open the ./file_hasher_files/file_hashes file
	/// and interprets it as an EDList.
	/// 
	/// If it is unable to open the file, it may ask the user
	/// whether it should create a new file, using an object implementing
	/// UserInterface.
	/// 
	/// Also writes a backup of the file_hashes file,
	/// to the file_hash_backups folder, when file_hashes has been read.
	pub fn open(user_interface: impl UserInterface, banlist: PathBanlist) -> Result<EDList, String> {
		let file = match File::open("./file_hasher_files/file_hashes") {
			Ok(file) => file,
			Err(err) => {
				loop {
					let answer = user_interface
						.get_user_answer(&format!("Could not open file_hashes, err = {}\nDo you wish to create a new file? YES/NO", err));
					if answer == "YES" {
						// Prevent a single pc corruption from jumping to the code where a clean EDList is returned.
						#[inline(never)]
						fn create_empty_e_d_list(user_interface: impl UserInterface, banlist: PathBanlist) -> Box<EDList> {
							user_interface.send_message("Created empty list");
							// Using Box such that the returned value from this function will not be valid
							// in case of the pc jumping to this place from the open method on EDList.
							// Even if the program should run successfully after making such a jump, it will
							// write an invalid xor_checksum to the hash_file, which will create an error the
							// next time the file is opened.
							Box::new(EDList::new(banlist))
						}
						return Ok(*create_empty_e_d_list(user_interface, banlist));
					}
					else if answer == "NO" {break;}
				}
				return Err("Failed to open file_hashes".to_string());
			}
		};

		let lines: Result<Vec<String>, String> = BufReader::new(file).lines().map(|x|{
			match x {
				Ok(x) => Ok(x),
				Err(err) => Err(format!("Error reading line, error message = {}", err))
			}
		}).collect();
		let mut lines = lines?.into_iter();

		// Handling list version.
		if let Some(first_line) = lines.next() {
			match EDList::get_version_from_line(first_line.as_ref()) {
				ListVersion::V1_1 => (),
				ListVersion::V1_0 => loop {
					let answer = user_interface
						.get_user_answer("List version is 1.0, do you want to update it to version 1.1? yes/no")
						.to_lowercase();
					match answer.as_ref() {
						"yes" => break,
						"no"  => return Err("File hasher cannot work without updating list version".to_string()),
						_     => user_interface.send_message("Invalid answer")
					}
				},
				ListVersion::MissingIdentifier => {
					user_interface.send_message("file_hashes is missing the list_version identifier");
					user_interface.send_message("This might mean this file_hashes list is from before V1.0.0\
					                             \nIf you want to update the list, use V1.0.0 of this program.");
					return Err("Missing list_version identifier".to_string());
				},
				ListVersion::InvalidVersion(version_identifier) => {
					return Err(format!(
						"Invalid version identifier \"{}\" \
						in file_hashes,\nmaybe the file is made by a future version of the program?", version_identifier))
				}
			}
		}
		else {return Err("Invalid file_hashes file".to_string());};

		let mut file_final_checksum: Option<String> = None;
		let mut file_xor_checksum: Option<[u8;HASH_OUTPUT_LENGTH]> = None;
		let mut xor_checksum = [0u8;HASH_OUTPUT_LENGTH];
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		let mut e_d_list = EDList::new(banlist);

		for line in lines {
			match EDList::identify_line(line.as_ref()) {
				LineType::FinChecksum(string) => {
					match file_final_checksum {
						None => file_final_checksum = Some(string),
						Some(_val) => return Err("More than one fin_checksum in file_hashes!".to_string())
					}
				},
				LineType::XorChecksum(string) => {
					match file_xor_checksum {
						None => {
							let mut new_xor_checksum = [0u8; HASH_OUTPUT_LENGTH];
							if let Err(_err) = decode_to_slice(string, &mut new_xor_checksum) {
								return Err("Invalid XORCHECKSUM in file_hashes".to_string());
							}
							file_xor_checksum = Some(new_xor_checksum);
						},
						Some(_val) => return Err("More than one xor_checksum in file_hashes!".to_string())
					}
				},
				LineType::EDElement => {
					let element = match EDElement::from_str(&line) {
						Ok(element) => element,
						Err(err) => return Err(format!("Error interpreting EDElement from file_hashes, line = {}, err = {}", line, err))
					};
					hasher.process(element.get_hash());
					xor_checksum.iter_mut().zip(element.get_hash().iter()).for_each(|(dst, src)| *dst ^= src);
					e_d_list.element_list.push(element);
				}
			}
		}

		// Unwrapping checksums and list_versions.
		let file_xor_checksum = if let Some(file_xor_checksum) = file_xor_checksum {file_xor_checksum}
		else {
			return Err("No xor_checksum was found in file_hashes\n\
			            if the file was created by an earlier version of the program,\n\
			            you might be able to update it using the version prior to 1.0.0".to_string());
		};

		hasher.process(&file_xor_checksum);
		let final_checksum = shared::blake2_to_string(hasher);

		let file_final_checksum = if let Some(file_final_checksum) = file_final_checksum {file_final_checksum}
		else {return Err("file_hashes missing final_checksum!".to_string())};

		// Verifying xor_checksum
		// By using the file_xor_checksum instead of xor_checksum, we can
		// make sure that any corruption would also trickle into the next
		// time the list is read.
		if file_xor_checksum != xor_checksum {return Err("Saved xor_checksum is not valid".to_string());}
		e_d_list.xor_checksum = file_xor_checksum;

		// Verifying final_checksum.
		if file_final_checksum != final_checksum {
			return Err("checksum in file_hashes is not valid!".to_string());
		}

		match e_d_list.write_backup() {
			Ok(_ok) => (),
			Err(err) => return Err(format!("Error writing backup, err = {}", err))
		}
		
		Ok(e_d_list)
	}

	/// Creates a new empty EDList.
	fn new(banlist: PathBanlist) -> EDList {
		EDList{element_list: Vec::new(), banlist, xor_checksum: [0u8; HASH_OUTPUT_LENGTH]}
	}

	/// Tests every element in the lists integrity against
	/// the real files and links, they refer to.
	/// Returns a vector with strings describing all the errors.
	/// Also sends a message to the UserInterface impl, for every
	/// element that is being tested.
	pub fn verify(&self, prefix:Option<&str>, user_interface: &impl UserInterface) -> Vec<String> {
		match prefix {
			Some(prefix) => {
				let element_list = &self.element_list;
				let mut elements_with_prefix:Vec<&EDElement> = Vec::with_capacity(element_list.len());
				for e_d_element in element_list {
					let path = e_d_element.get_path();
					if shared::prefix_split(prefix, path).is_some() {
						elements_with_prefix.push(e_d_element);
					}
				}
				self.verify_loop(&elements_with_prefix, user_interface)
			}
			None => self.verify_loop(&self.element_list, user_interface)
		}
	}

	/// Goes through all the elements in the given element_list.
	/// It returns a list of all the errors in a string format.
	fn verify_loop<T: AsRef<EDElement>>(&self, element_list: &[T], user_interface: &impl UserInterface) -> Vec<String> {
		let mut error_list = Vec::new();
		let list_length = element_list.len();
		let list_length_width = list_length.to_string().chars().count();

		for (file_count, e_d_element) in element_list.iter().enumerate() {
			let path = e_d_element.as_ref().get_path();
			user_interface.send_message(&format!("Verifying file {:0width$} of {} = {}", file_count + 1, list_length, path, width=list_length_width));

			match e_d_element.as_ref().test_integrity() {
				Ok(()) => (),
				Err(error_message) => error_list.push(error_message)
			}
			if self.banlist.is_in_banlist(path) {
				error_list.push(format!("\"{}\" is in the banlist.", path));
			}
		}
		error_list
	}

	/// Finds all the paths that are deleted, or modified
	/// and removes them from the list, if the user agrees.
	/// Also removes files that has a prefix in the banlist.
	/// If the file has a prefix in the banlist, we do not test
	/// its metadata.
	pub fn delete(&mut self, user_interface: &impl UserInterface) {
		let old_list_len = self.element_list.len();
		let old_list = std::mem::replace(&mut self.element_list, Vec::with_capacity(old_list_len));
		let new_list = &mut self.element_list;

		let mut cont_delete = false;
		let mut deleted_paths:Vec<String> = Vec::new();

		let xor_checksum = &mut self.xor_checksum;

		let mut delete_element = |e_d_element:EDElement| {
			xor_checksum.iter_mut().zip(e_d_element.get_hash().iter()).for_each(|(dest, hash_part)| *dest ^= *hash_part);
			deleted_paths.push(e_d_element.take_path());
		};

		for e_d_element in old_list.into_iter() {
			let mut error = 
			if self.banlist.is_in_banlist(e_d_element.get_path()) {
				Some(format!("Path {} is in the banlist", e_d_element.get_path()))
			}
			else {None};

			if error.is_none() {
				match e_d_element.test_metadata() {
					Ok(()) => (),
					Err(err) => error = Some(err)
				}
			}
			match error {
				None => new_list.push(e_d_element),
				Some(err) => loop {
					if cont_delete {
						delete_element(e_d_element);
						break;
					}
					let answer = user_interface.get_user_answer(&format!("{}\nDo you wish to delete this path? YES/NO/CONTYES", err));
					match answer.as_str() {
						"YES" => {
							delete_element(e_d_element);
							break;
						},
						"NO" => {
							new_list.push(e_d_element);
							break;
						},
						"CONTYES" => cont_delete = true,
						_ => ()
					}
				}
			}
		}
		let deleted_paths_length = old_list_len - new_list.len();
		if deleted_paths.len() != deleted_paths_length {panic!("Invalid amount of elements deleted.");}

		if !deleted_paths.is_empty() {
			let length_width = deleted_paths_length.to_string().chars().count();
			user_interface.send_message(&format!("Deleted paths, amount = {}", deleted_paths_length));
			for (index, deleted_path) in deleted_paths.iter().enumerate() {
				user_interface.send_message(&format!("{:0width$} of {}: {}", index + 1, deleted_paths_length, deleted_path, width=length_width));
			}
		}
	}

	/// Finds all the files that have not been
	/// added to the list yet, and puts them into the list.
	/// It gives messages of all the elements it is hashing
	/// to the user_interface, while it is in progress.
	/// 
	/// In case of an error when reading the file_index_list,
	/// we return an error.
	/// 
	/// When this function returns Ok, it returns a list with
	/// all the errors created when trying to read files.
	pub fn create(&mut self, user_interface: &impl UserInterface) -> Result<Vec<String>, String> {
		let mut pending_hashing = Vec::new();
		let mut existing_paths = std::collections::HashSet::with_capacity(self.element_list.len());
		for element in &self.element_list {
			existing_paths.insert(element.get_path());
		}

		let index_strings = match self.index(".") {
			Ok(strings) => strings,
			Err(err) => return Err(format!("Error indexing files, Err = {}", err))
		};

		for string in index_strings {
			if !existing_paths.contains(string.as_str()) {
				pending_hashing.push(string);
			}
		}

		let mut errors = Vec::new();

		let pending_hashing_length = pending_hashing.len();
		let pending_hashing_length_width = pending_hashing_length.to_string().chars().count();
		for (i, string) in pending_hashing.into_iter().enumerate() {
			user_interface.send_message(&format!("Hashing file {:0width$} of {} = {}", i+1,
			                            pending_hashing_length, string, width=pending_hashing_length_width));
			match EDElement::from_path(string) {
				Ok(new_element) => self.add_e_d_element(new_element),
				Err(err) => errors.push(err)
			};
		}

		Ok(errors)
	}

	/// Sort this EDList according to the paths of the EDElements.
	pub fn sort(&mut self) {
		use std::cmp::Ordering;
		self.element_list.sort_unstable_by(|a:&EDElement,b:&EDElement| {
			let mut split_a = a.get_path().split('/');
			let mut split_b = b.get_path().split('/');

			let mut cmp_state = Ordering::Equal;
			
			let mut a_next = split_a.next();
			let mut b_next = split_b.next();
			while let (Some(a), Some(b)) = (a_next, b_next) {
				if cmp_state != Ordering::Equal {
					// If we get here then both are subdirectories, with different roots.
					return cmp_state;
				}
				if cmp_state == Ordering::Equal {
					cmp_state = a.cmp(b);
				}
				
				a_next = split_a.next();
				b_next = split_b.next();
			}
			
			if let Some(_block) = a_next {
				// If we get here, then a has a next, but b doesn't
				Ordering::Greater
			}
			else if let Some(_block) = b_next {
				// If we get here, then b has a next, but a doesn't
				Ordering::Less
			}
			else {cmp_state}
		});
	}

	/// Sends a list of all the links that have the same
	/// link_target as at least one other link
	/// to the struct implementing UserInterface.
	/// 
	/// Also sends a list of all the files that have the
	/// same file_hash as at least one other file to the
	/// struct implementing UserInterface.
	pub fn find_duplicates(&self, user_interface: &impl UserInterface) {
		use std::collections::hash_map::Entry;
		let mut link_dups:HashMap<&str, Vec<&EDElement>> = HashMap::with_capacity(self.element_list.len());
		let mut file_dups:HashMap<[u8; HASH_OUTPUT_LENGTH], Vec<&EDElement>> = HashMap::with_capacity(self.element_list.len());
		for element in &self.element_list {
			match element.get_variant() {
				e_d_element::EDVariantFields::File(file) => {
					match file_dups.entry(file.file_hash) {
						Entry::Occupied(entry) => entry.into_mut().push(element),
						Entry::Vacant(entry) => {
							entry.insert(vec!(element));
						}
					}
				},
				e_d_element::EDVariantFields::Link(link) => {
					match link_dups.entry(&link.link_target) {
						Entry::Occupied(entry) => entry.into_mut().push(element),
						Entry::Vacant(entry) => {
							entry.insert(vec!(element));
						}
					}
				}
			}
		}

		let mut collision_blocks = 0;
		user_interface.send_message("Links with same target path:");
		for (key, vector) in link_dups {
			if vector.len() <= 1 {continue;}
			collision_blocks += 1;
			user_interface.send_message(&format!("{:4}links with target path = \"{}\":", "", key));
			for element in vector {
				user_interface.send_message(&format!("{:8}{}","", element.get_path()));
			}
		}
		user_interface.send_message("Files with the same checksum:");
		for (hash, vector) in file_dups {
			if vector.len() <= 1 {continue;}
			collision_blocks += 1;
			user_interface.send_message(&format!("{:4}Files with checksum = \"{}\":", "", shared::hash_to_string(&hash)));
			for element in vector {
				user_interface.send_message(&format!("{:8}{}", "", element.get_path()));
			}
		}
		user_interface.send_message(&format!("{} unique collisions found",collision_blocks));
	}

	/// Returns a complete list of all files
	/// from the given root directory.
	/// Does not follow symbolic links, but symbolic links are indexed
	/// as a normal file.
	/// Does not index paths that are in the banlist.
	fn index(&self, path:&str) -> Result<Vec<String>, String> {
		let entries = match std::fs::read_dir(path) {
			Ok(dirs) => dirs,
			Err(err) => return Err(format!("Error getting subdirs from dir {}, error = {}", path, err))
		};
		let mut index_list:Vec<String> = Vec::new();
		
		for entry in entries {
			let (entry, file_type) = match entry {
				Ok(entry) => match entry.file_type() {
					Ok(file_type) => (entry, file_type),
					Err(_err) => return Err("Error getting file type of index".to_string())
				},
				Err(_err) => return Err("Error iterating indexes".to_string())
			};

			let file_path = match entry.file_name().into_string() {
				Ok(file_name) => format!("{}/{}", path, file_name),
				Err(_err) => return Err(format!("Failed to convert OsString to String in path: {}", path))
			};
			// If file_path is in banlist, we should not index it.
			if self.banlist.is_in_banlist(&file_path) {continue;}
			if file_type.is_dir() {
				let sub_list =  match self.index(&file_path) {
					Ok(list) => list,
					Err(err) => return Err(err)
				};
				for element in sub_list {
					index_list.push(element);
				}
			}
			else {
				// File is either a normal file, or a symbolic link.
				index_list.push(file_path);
			}
		}
		Ok(index_list)
	}

	fn get_version_from_line(line: &str) -> ListVersion {
		if let Some(version) = shared::prefix_split(LIST_VERSION_PREFIX, line) {
			match version {
				"1.1" => ListVersion::V1_1,
				"1.0" => ListVersion::V1_0,
				identifier => ListVersion::InvalidVersion(identifier)
			}
		}
		else {
			ListVersion::MissingIdentifier
		}
	}
	/// Identifies a line as either some prefixed value,
	/// or an EDElement in String form.
	///
	/// Used to determine how the string should be processed.
	fn identify_line(line: &str) -> LineType {
		// Figure out whether line is a checksum.
		if let Some(checksum) = shared::prefix_split(FIN_CHECKSUM_PREFIX, line) {
			LineType::FinChecksum(checksum.to_string())
		}
		else if let Some(checksum) = shared::prefix_split(XOR_CHECKSUM_PREFIX, line) {
			LineType::XorChecksum(checksum.to_string())
		}
		// If line is not identified as any of the prefixed variants, it must be an EDElement.
		else {LineType::EDElement}
	}

	/// This is the only method that must be used to add elements
	/// to the EDList after it is initialized.
	/// It handles updating the lists internal xor checksum.
	fn add_e_d_element(&mut self, element:EDElement) {
		for (dest, hash_part) in self.xor_checksum.iter_mut().zip(element.get_hash().iter()) {
			*dest ^= *hash_part;
		}
		self.element_list.push(element);
	}

	/// Write EDList to ./file_hasher_files/file_hashes
	pub fn write_hash_file(&self) -> Result<(), String> {
		match File::create("./file_hasher_files/file_hashes") {
			Ok(mut file) => self.write_to_file(&mut file, "file_hashes"),
			Err(err) => Err(format!("Error creating file, Error = {}", err))
		}
	}

	fn write_backup(&self) -> Result<(), String> {
		let backup_dir = "./file_hasher_files/hash_file_backups";
		match create_dir_all(backup_dir) {
			Ok(_res) => (),
			Err(err) => return Err(format!("Error creating hash_file_backups directory, Error = {}", err))
		};
		let local: DateTime<Local> = Local::now();
		let mut file = match File::create(format!("{}/{}", backup_dir, local)) {
			Ok(file) => file,
			Err(err) => return Err(format!("Error creating backup file, err = {}", err))
		};

		self.write_to_file(&mut file, "hashbackup")
	}

	/// Used when we need to write hash_file data to a file
	/// Also used for writing the backups to file.
	fn write_to_file(&self, file:&mut File, file_name:&str) -> Result<(), String> {
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		let mut element_string = String::new();

		for element in &self.element_list {
			element_string.push_str(format!("{}\n", element).as_ref());
			hasher.process(element.get_hash());
		}
		hasher.process(&self.xor_checksum);

		let list_version_string = format!("{}{}\n", LIST_VERSION_PREFIX, CURRENT_LIST_VERSION);
		let xor_checksum_string = format!("{}{}\n", XOR_CHECKSUM_PREFIX, shared::hash_to_string(&self.xor_checksum));
		let fin_checksum_string = format!("{}{}\n", FIN_CHECKSUM_PREFIX, shared::blake2_to_string(hasher));

		let final_string = format!("{}{}{}{}", list_version_string, xor_checksum_string, fin_checksum_string, element_string);

		if let Err(err) = file.write_all(final_string.as_bytes()) {
			return Err(format!("Error writing to the file {}. err = {}", file_name, err));
		}

		if let Err(err) = file.flush() {
			return Err(format!("Error writing to the file {}. err = {}", file_name, err));
		}
		
		Ok(())
	}

	/// Used to generate a checksum, using only EDElemnts
	/// whose path contains the relative path.
	/// 
	/// To minimize user errors, a relative_path must end
	/// with a forward slash.
	/// 
	/// The relative_path part of the EDElements will not be
	/// included in the generated checksum.
	/// This makes it possible to compare to another different
	/// paths checksum.
	pub fn relative_checksum(&self, user_interface: &impl UserInterface) {
		let relative_path = loop {
			let relative_path = user_interface.get_user_answer("Enter the relative path:");
			// We should only accept a relative path that ends in a forward slash.
			if let Some('/') = relative_path.chars().rev().next() {
				break relative_path;
			}
			else {
				user_interface.send_message("The relative path must end with a forward slash \"/\"");
			}
		};
		
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		let mut elements_found = false;
		self.element_list.iter()
		    .filter(|e_d_element| shared::prefix_split(relative_path.as_ref(), e_d_element.get_path()).is_some())
		    .for_each(|e_d_element|
		{
			elements_found = true;
			hasher.process(&e_d_element.get_path().as_bytes()[relative_path.len()..]);
			hasher.process(&e_d_element.get_modified_time().to_le_bytes());
			match e_d_element.get_variant() {
				e_d_element::EDVariantFields::File(file) => hasher.process(&file.file_hash),
				e_d_element::EDVariantFields::Link(link) => hasher.process(&link.link_target.as_bytes())
			}
		});
		if elements_found {
			user_interface.send_message(&format!("Relative hash:\n{}", shared::blake2_to_string(hasher)));
		}
		else {
			user_interface.send_message("No files were found in the specified path");
		}
	}
}