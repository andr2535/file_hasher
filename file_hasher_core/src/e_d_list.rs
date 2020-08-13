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


pub mod errors;
pub mod e_d_element;

use errors::*;
use self::e_d_element::EDElement;
use std::convert::TryFrom;
use super::{shared, shared::{Checksum, UserInterface, constants::*}};
use super::path_banlist::PathBanlist;

use chrono::prelude::{DateTime, Local};
use blake2::{VarBlake2b, digest::{Update, VariableOutput}};
use rayon::prelude::*;
use join::try_join;
use std::{fs::{File, create_dir_all}, io::{BufRead, BufReader, Write}, collections::HashMap};

enum ListVersion<'a> {
	V1_0,
	V1_1,
	MissingIdentifier,
	InvalidVersion(&'a str)
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
	xor_checksum: Checksum
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
	pub fn open(user_interface: impl UserInterface, banlist: PathBanlist) -> Result<EDList, EDListOpenError> {
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
							Box::new(EDList::new(banlist, Vec::new(), Checksum::default()))
						}
						return Ok(*create_empty_e_d_list(user_interface, banlist));
					}
					else if answer == "NO" {break;}
				}
				return Err(EDListOpenError::CouldNotOpenFileHashesFile);
			}
		};

		let mut lines = BufReader::new(file).lines().collect::<Result<Vec<_>, _>>()?.into_iter();
		
		let (version_line, xor_checksum_line, fin_checksum_line) = 
		    if let Some((version_line, xor_checksum_line, fin_checksum_line)) = 
		    try_join!(lines.next(), lines.next(), lines.next()) {
			(version_line, xor_checksum_line, fin_checksum_line)
		} else {return Err(EDListOpenError::ChecksumsMissingError)};
		
		// Handling list version.
		match EDList::get_version_from_line(version_line.as_ref()) {
			ListVersion::V1_1 => (),
			ListVersion::V1_0 => Err(UnsupportedEDListVersion::V1_0)?,
			ListVersion::MissingIdentifier => Err(UnsupportedEDListVersion::MissingIdentifier)?,
			ListVersion::InvalidVersion(version_identifier) => 
				Err(UnsupportedEDListVersion::Invalid(version_identifier.to_owned()))?
		}
		
		// Parsing file_xor_checksum
		let file_xor_checksum = {
			let xor_checksum_string = if let Some(xor_checksum_string) = 
			    xor_checksum_line.strip_prefix(XOR_CHECKSUM_PREFIX) 
			{
				xor_checksum_string
			} else {Err(EDListOpenError::InvalidXorChecksum)?};

			let mut xor_checksum = Checksum::default();
			hex::decode_to_slice(xor_checksum_string, &mut *xor_checksum)?;
			xor_checksum
		};

		// Parsing file_final_checksum
		let file_final_checksum = {
			if let Some(fin_checksum_string) = fin_checksum_line.strip_prefix(FIN_CHECKSUM_PREFIX) {
				fin_checksum_string
			} else {Err(EDListOpenError::InvalidFinChecksum)?}
		};
		let mut xor_checksum = Checksum::default();
		let mut hasher = VarBlake2b::new(HASH_OUTPUT_LENGTH).unwrap();

		// Parsing all EDElements.
		let e_d_elements = lines.collect::<Vec<_>>().par_iter().enumerate()
			.map(|(i, line)| EDElement::try_from(line.as_ref()).map_err(|err| (err, i)))
			.collect::<Result<Vec<_>, _>>()?;

		// Processing the checksums, so that we can verify the integrity
		// of the file before returning.
		e_d_elements.iter().for_each(|element| {
			hasher.update(element.get_hash().as_ref());
			xor_checksum ^= element.get_hash();
		});
		hasher.update(file_xor_checksum.as_ref());
		let final_checksum = shared::blake2_to_string(hasher);
		
		// By creating the EDList object before comparing xor_checksum with
		// the one saved in the file_hashes file, we hopefully avoid any optimizations
		// that would prevent the edlist from using the generated xorchecksum, after comparison.
		let e_d_list = EDList::new(banlist, e_d_elements, file_xor_checksum);

		// Verifying xor_checksum
		if e_d_list.xor_checksum != xor_checksum {Err(EDListOpenError::XorChecksumMismatch)?}

		// Verifying final_checksum.
		if file_final_checksum != final_checksum {Err(EDListOpenError::FinChecksumMismatch)?}
		
		e_d_list.write_backup()?;
		
		Ok(e_d_list)
	}

	/// Creates a new empty EDList.
	fn new(banlist: PathBanlist, element_list: Vec<EDElement>, xor_checksum: Checksum) -> EDList {
		EDList{element_list, banlist, xor_checksum}
	}

	/// Tests every element in the lists integrity against
	/// the real files and links, they refer to.
	/// Returns a vector with strings describing all the errors.
	/// Also sends a message to the UserInterface impl, for every
	/// element that is being tested.
	pub fn verify(&self, prefix:Option<&str>, user_interface: &impl UserInterface) -> Vec<VerifyError> {
		match prefix {
			Some(prefix) => {
				let element_list = &self.element_list;
				let mut elements_with_prefix:Vec<&EDElement> = Vec::with_capacity(element_list.len());
				for e_d_element in element_list {
					let path = e_d_element.get_path();
					if path.strip_prefix(prefix).is_some() {
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
	fn verify_loop<T: AsRef<EDElement>>(&self, element_list: &[T], user_interface: &impl UserInterface) -> Vec<VerifyError> {
		let mut error_list = Vec::new();
		let list_length = element_list.len();
		let list_length_width = list_length.to_string().chars().count();

		for (file_count, e_d_element) in element_list.iter().enumerate() {
			let path = e_d_element.as_ref().get_path();
			user_interface.send_message(&format!("Verifying file {:0width$} of {} = {}", file_count + 1, list_length, path, width=list_length_width));

			if let Err(err) = e_d_element.as_ref().test_integrity() {
				error_list.push(err.into());
			}
			if self.banlist.is_in_banlist(path) {
				error_list.push(VerifyError::PathInBanlist(path.to_string()));
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
			*xor_checksum ^= e_d_element.get_hash();
			deleted_paths.push(e_d_element.take_path());
		};

		for e_d_element in old_list.into_iter() {
			let mut error = 
			if self.banlist.is_in_banlist(e_d_element.get_path()) {
				Some(format!("Path {} is in the banlist", e_d_element.get_path()))
			}
			else {None};

			if error.is_none() {
				if let Err(err) = e_d_element.test_metadata() {
					error = Some(err.to_string());
				}
			}
			match error {
				None => new_list.push(e_d_element),
				Some(err) => loop {
					if cont_delete {
						delete_element(e_d_element);
						break;
					}
					let answer = user_interface.get_user_answer(&format!("{}\nDo you wish to delete this path? yes/no/contyes", err));
					match answer.to_lowercase().as_str() {
						"yes" => {
							delete_element(e_d_element);
							break;
						},
						"no" => {
							new_list.push(e_d_element);
							break;
						},
						"contyes" => cont_delete = true,
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
	pub fn create(&mut self, user_interface: &impl UserInterface) -> Result<Vec<CreateError>, CreateError> {
		let mut pending_hashing = Vec::new();
		let mut existing_paths = std::collections::HashSet::with_capacity(self.element_list.len());
		for element in &self.element_list {
			existing_paths.insert(element.get_path());
		}

		let index_strings = self.index(".", user_interface)?;

		for string in index_strings {
			if !existing_paths.contains(string.as_str()) {
				pending_hashing.push(string);
			}
		}

		let mut errors: Vec<CreateError> = Vec::new();

		let pending_hashing_length = pending_hashing.len();
		let pending_hashing_length_width = pending_hashing_length.to_string().chars().count();
		for (i, string) in pending_hashing.into_iter().enumerate() {
			user_interface.send_message(&format!("Hashing file {:0width$} of {} = {}", i+1,
			                            pending_hashing_length, string, width=pending_hashing_length_width));
			match EDElement::from_path(string) {
				Ok(new_element) => self.add_e_d_element(new_element),
				Err(err) => errors.push(err.into())
			};
		}

		Ok(errors)
	}

	/// Sort this EDList according to the paths of the EDElements.
	pub fn sort(&mut self) {
		use std::cmp::Ordering;
		self.element_list.par_sort_unstable_by(|a:&EDElement,b:&EDElement| {
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
	/// TODO: Fix issue where relative checksum that is moved along with target, doesn't generate a duplicate.
	pub fn find_duplicates(&self, user_interface: &impl UserInterface) {
		use std::collections::hash_map::Entry;
		let mut link_dups:HashMap<&str, Vec<&EDElement>> = HashMap::with_capacity(self.element_list.len());
		let mut file_dups:HashMap<Checksum, Vec<&EDElement>> = HashMap::with_capacity(self.element_list.len());
		for element in &self.element_list {
			match element.get_variant() {
				e_d_element::EDVariantFields::File(file) => {
					match file_dups.entry(file.file_checksum) {
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
		user_interface.send_message("Links with same target path and origin directory:");
		link_dups.iter().filter(|(_, v)| v.len() > 1).for_each(|(key, vector)| {
			collision_blocks += 1;
			user_interface.send_message(&format!("{:4}links with target path = \"{}\":", "", key));
			for element in vector {
				user_interface.send_message(&format!("{:8}{}","", element.get_path()));
			}
		});
		user_interface.send_message("Files with the same checksum:");
		file_dups.iter().filter(|(_, v)| v.len() > 1).for_each(|(hash, vector)| {
			collision_blocks += 1;
			user_interface.send_message(&format!("{:4}Files with checksum = \"{}\":", "", hex::encode_upper(hash.as_ref())));
			for element in vector {
				user_interface.send_message(&format!("{:8}{}", "", element.get_path()));
			}
		});
		user_interface.send_message(&format!("{} unique collisions found",collision_blocks));
	}

	/// Returns a complete list of all files
	/// from the given root directory.
	/// Does not follow symbolic links, but symbolic links are indexed
	/// as a normal file.
	/// 
	/// Does not index if, file is not a regular readable file, or a symbolic link.
	/// Does not index paths that are in the banlist.
	fn index(&self, path: &str, interfacer: &impl UserInterface) -> Result<Vec<String>, IndexError> {
		let entries = std::fs::read_dir(path)
			.map_err(|err| IndexError::CantGetSubDirError(path.to_string(), err.to_string()))?;
		let mut index_list:Vec<String> = Vec::new();
		
		for entry in entries {
			let entry = entry?;
			let file_type = entry.file_type()?;

			let file_path = format!("{}/{}", path,
				entry.file_name().into_string()
					.map_err(|_|IndexError::OsStringConvertError(path.to_string()))?);
			// If file_path is in banlist, we should not index it.
			if self.banlist.is_in_banlist(&file_path) {continue;}
			if file_type.is_dir() {
				for element in self.index(&file_path, interfacer)? {
					index_list.push(element);
				}
			}
			else if file_type.is_file() || file_type.is_symlink() {
				index_list.push(file_path);
			}
			else {
				interfacer.send_message(
					format!(
						"The file \"{}\" is neither a readable file, a symbolic link or a directory, \
						and was skipped during file indexing.", 
						file_path).as_ref());
			}
		}
		Ok(index_list)
	}

	fn get_version_from_line(line: &str) -> ListVersion {
		match line.strip_prefix(LIST_VERSION_PREFIX) {
			Some("1.1") => ListVersion::V1_1,
			Some("1.0") => ListVersion::V1_0,
			Some(identifier) => ListVersion::InvalidVersion(identifier),
			None => ListVersion::MissingIdentifier
		}
	}

	/// This is the only method that must be used to add elements
	/// to the EDList after it is initialized.
	/// It handles updating the lists internal xor checksum.
	fn add_e_d_element(&mut self, element:EDElement) {
		self.xor_checksum ^= element.get_hash();
		self.element_list.push(element);
	}

	/// Write EDList to ./file_hasher_files/file_hashes
	pub fn write_hash_file(&self) -> Result<(), WriteHashFileError> {
		let mut file = File::create("./file_hasher_files/file_hashes")
			.map_err(|err|WriteHashFileError::ErrorCreatingFile(err.to_string()))?;
		self.write_edlist_to_file(&mut file, "file_hashes")?;
		Ok(())
	}

	fn write_backup(&self) -> Result<(), WriteBackupError> {
		const BACKUP_DIR:&str = "./file_hasher_files/hash_file_backups";
		create_dir_all(BACKUP_DIR).map_err(|err| WriteBackupError::CreateDirectoryError(err.to_string()))?;
		let local: DateTime<Local> = Local::now();
		let mut file = File::create(format!("{}/{}", BACKUP_DIR, local))
			.map_err(|err| WriteBackupError::CreateFileError(err.to_string()))?;
		self.write_edlist_to_file(&mut file, "hashbackup")?;
		Ok(())
	}

	/// Used when we need to write hash_file data to a file
	/// Also used for writing the backups to file.
	fn write_edlist_to_file(&self, file: &mut File, file_name: &str) -> Result<(), WriteEDListToFileError> {
		let mut hasher = VarBlake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		let mut element_string = String::new();

		for element in &self.element_list {
			element_string.push_str(format!("{}\n", element).as_ref());
			hasher.update(element.get_hash().as_ref());
		}
		hasher.update(&self.xor_checksum.as_ref());

		let list_version_string = format!("{}{}\n", LIST_VERSION_PREFIX, CURRENT_LIST_VERSION);
		let xor_checksum_string = format!("{}{}\n", XOR_CHECKSUM_PREFIX, hex::encode_upper(&self.xor_checksum.as_ref()));
		let fin_checksum_string = format!("{}{}\n", FIN_CHECKSUM_PREFIX, shared::blake2_to_string(hasher));

		let final_string = format!("{}{}{}{}", list_version_string, xor_checksum_string, fin_checksum_string, element_string);

		file.write_all(final_string.as_bytes())
			.map_err(|err| WriteEDListToFileError::WriteError(file_name.to_string(), err.to_string()))?;

		file.flush()
			.map_err(|err| WriteEDListToFileError::FlushError(file_name.to_string(), err.to_string()))?;
		
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

		let mut hasher = VarBlake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		let mut elements_found = false;
		self.element_list.iter()
		    .filter_map(|e_d_element| try_join!(Some(e_d_element), e_d_element.get_path().strip_prefix(relative_path.as_ref() as &str)))
		    .for_each(|(e_d_element, postfix)|
		{
			elements_found = true;
			hasher.update(postfix.as_bytes());
			hasher.update(&e_d_element.get_modified_time().to_le_bytes());
			match e_d_element.get_variant() {
				e_d_element::EDVariantFields::File(file) => hasher.update(&file.file_checksum.as_ref()),
				e_d_element::EDVariantFields::Link(link) => hasher.update(&link.link_target.as_bytes())
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