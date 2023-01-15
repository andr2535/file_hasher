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
pub mod errors;

use std::{
	collections::HashMap,
	convert::TryFrom,
	fs::{canonicalize, create_dir_all, File},
	io::{BufRead, BufReader, Write},
	path::Path,
};

use blake2::{
	digest::{Update, VariableOutput},
	Blake2bVar,
};
use chrono::prelude::{DateTime, Local};
use errors::*;
use join::try_join;
use rayon::prelude::*;

use self::e_d_element::EDElement;
use super::{
	path_banlist::PathBanlist,
	shared,
	shared::{constants::*, Checksum, SlashEnding, StubUserInterface, UserInterface, YesNo, YesNoAuto},
};

enum ListVersion<'a> {
	V1_0,
	V1_1,
	MissingIdentifier,
	InvalidVersion(&'a str),
}

#[derive(Debug)]
enum FileOperation {
	Delete(String),
	Move { from: String, to: String },
	Copy { from: String, to: String },
}
impl std::fmt::Display for FileOperation {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		use FileOperation::*;
		let from_convert = |from| {
			canonicalize(&from)
				.map(|from| from.to_str().unwrap().to_string())
				.unwrap_or(format!("'''Error getting canonical path of {}'''", from))
		};

		match self {
			Delete(path) => write!(f, "Delete {}", path),
			Move { from, to } => write!(f, "Move {} to {}", from_convert(from), to),
			Copy { from, to } => write!(f, "Copy {} to {}", from_convert(from), to),
		}
	}
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
#[derive(Debug, Clone)]
pub struct EDList {
	element_list: Vec<EDElement>,
	banlist:      PathBanlist,
	xor_checksum: Checksum,
	root_path:    String,
}
impl EDList {
	/// Attempts to open the {root_path}/file_hasher_files/file_hashes file
	/// and interprets it as an EDList.
	///
	/// If it is unable to open the file, it may ask the user
	/// whether it should create a new file, using an object implementing
	/// UserInterface.
	///
	/// Also writes a backup of the file_hashes file,
	/// to the file_hash_backups folder, when file_hashes has been read.
	pub fn open(root_path: &str, user_interface: &impl UserInterface, banlist: PathBanlist) -> Result<EDList, EDListOpenError> {
		let file = match File::open(format!("{}/file_hasher_files/file_hashes", root_path)) {
			Ok(file) => file,
			Err(err) => {
				let answer: YesNo = user_interface
					.get_user_answer(&format!("Could not open file_hashes, err = {}\nDo you wish to create a new file?", err));
				if answer == YesNo::Yes {
					// Prevent a single pc corruption from jumping to the code where a clean EDList is returned.
					#[inline(never)]
					fn create_empty_e_d_list(user_interface: &impl UserInterface, root_path: &str, banlist: PathBanlist) -> Box<EDList> {
						user_interface.send_message("Created empty list");
						// Using Box such that the returned value from this function will not be valid
						// in case of the pc jumping to this place from the open method on EDList.
						// Even if the program should run successfully after making such a jump, it will
						// write an invalid xor_checksum to the hash_file, which will create an error the
						// next time the file is opened.
						Box::new(EDList::new(root_path.to_string(), banlist, Vec::new(), Checksum::default()))
					}
					return Ok(*create_empty_e_d_list(user_interface, root_path, banlist));
				}
				else {
					return Err(EDListOpenError::CouldNotOpenFileHashesFile);
				}
			},
		};

		let mut lines = BufReader::new(file).lines().collect::<Result<Vec<_>, _>>()?.into_iter();

		let (version_line, xor_checksum_line, fin_checksum_line) =
			try_join!(lines.next(), lines.next(), lines.next()).ok_or(EDListOpenError::ChecksumsMissingError)?;

		// Handling list version.
		match EDList::get_version_from_line(version_line.as_ref()) {
			ListVersion::V1_1 => (),
			ListVersion::V1_0 => Err(UnsupportedEDListVersion::V1_0)?,
			ListVersion::MissingIdentifier => Err(UnsupportedEDListVersion::MissingIdentifier)?,
			ListVersion::InvalidVersion(version_identifier) => Err(UnsupportedEDListVersion::Invalid(version_identifier.to_owned()))?,
		}

		// Parsing file_xor_checksum
		let file_xor_checksum = if let Some(xor_checksum_string) = xor_checksum_line.strip_prefix(XOR_CHECKSUM_PREFIX) {
			let mut xor_checksum = Checksum::default();
			hex::decode_to_slice(xor_checksum_string, &mut *xor_checksum)?;
			xor_checksum
		}
		else {
			Err(EDListOpenError::InvalidXorChecksum)?
		};

		// Parsing file_final_checksum
		let file_final_checksum = fin_checksum_line.strip_prefix(FIN_CHECKSUM_PREFIX).ok_or(EDListOpenError::InvalidFinChecksum)?;
		let mut xor_checksum = Checksum::default();
		let mut hasher = Blake2bVar::new(HASH_OUTPUT_LENGTH).unwrap();

		// Parsing all EDElements.
		let e_d_elements = lines
			.collect::<Vec<_>>()
			.into_par_iter()
			.enumerate()
			.map(|(i, line)| EDElement::try_from(line.as_ref()).map_err(|err| (err, i)))
			.collect::<Result<Vec<_>, _>>()?;

		// Processing the checksums, so that we can verify the integrity
		// of the file before returning.
		e_d_elements.iter().for_each(|element| {
			hasher.update(element.get_hash().as_ref());
			xor_checksum ^= element.get_hash();
		});
		hasher.update(file_xor_checksum.as_ref());
		let final_checksum = shared::blake2_to_checksum(hasher);

		// By creating the EDList object before comparing xor_checksum with
		// the one saved in the file_hashes file, we hopefully avoid any optimizations
		// that would prevent the edlist from using the generated xorchecksum, after comparison.
		let e_d_list = EDList::new(root_path.to_string(), banlist, e_d_elements, file_xor_checksum);

		// Verifying xor_checksum
		if e_d_list.xor_checksum != xor_checksum {
			Err(EDListOpenError::XorChecksumMismatch)?
		}

		// Verifying final_checksum.
		if file_final_checksum != final_checksum.to_string() {
			Err(EDListOpenError::FinChecksumMismatch)?
		}

		e_d_list.write_backup()?;

		Ok(e_d_list)
	}

	/// Creates a new empty EDList.
	fn new(root_path: String, banlist: PathBanlist, element_list: Vec<EDElement>, xor_checksum: Checksum) -> EDList {
		EDList { element_list, banlist, xor_checksum, root_path }
	}

	/// Tests every element in the lists integrity against
	/// the real files and links, they refer to.
	/// Returns a vector with strings describing all the errors.
	/// Also sends a message to the UserInterface impl, for every
	/// element that is being tested.
	pub fn verify(&self, prefix: Option<&str>, user_interface: &impl UserInterface) -> Vec<VerifyError> {
		if let Some(prefix) = prefix {
			let prefix_elements: Vec<_> = self.element_list.iter().filter(|e| e.get_path().strip_prefix(prefix).is_some()).collect();
			self.verify_loop(&prefix_elements, user_interface)
		}
		else {
			self.verify_loop(&self.element_list, user_interface)
		}
	}

	/// Verify all symbolic links in the EDList.
	pub fn verify_links(&self, user_interface: &impl UserInterface) -> Vec<VerifyError> {
		let link_elements: Vec<_> = self.element_list.iter().filter(|e| e.get_variant().is_link()).collect();
		self.verify_loop(&link_elements, user_interface)
	}

	/// Goes through all the elements in the given element_list.
	/// It returns a list of all the errors in a string format.
	fn verify_loop<T: AsRef<EDElement>>(&self, element_list: &[T], user_interface: &impl UserInterface) -> Vec<VerifyError> {
		let mut error_list = Vec::new();
		let list_length = element_list.len();
		let list_length_width = list_length.to_string().chars().count();

		for (file_count, e_d_element) in element_list.iter().enumerate() {
			let path = e_d_element.as_ref().get_path();
			user_interface.send_message(&format!(
				"Verifying file {:0width$} of {} = {}",
				file_count + 1,
				list_length,
				path,
				width = list_length_width
			));

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

		let mut auto_action: Option<YesNo> = None;
		let mut deleted_paths: Vec<String> = Vec::new();

		let xor_checksum = &mut self.xor_checksum;

		let mut delete_element = |e_d_element: EDElement| {
			*xor_checksum ^= e_d_element.get_hash();
			deleted_paths.push(e_d_element.take_path());
		};

		for e_d_element in old_list.into_iter() {
			let mut error = if self.banlist.is_in_banlist(e_d_element.get_path()) {
				Some(format!("Path {} is in the banlist", e_d_element.get_path()))
			}
			else {
				None
			};

			if error.is_none() {
				if let Err(err) = e_d_element.test_metadata() {
					error = Some(err.to_string());
				}
			}
			match error {
				None => new_list.push(e_d_element),
				Some(err) => {
					let answer = if let Some(auto_value) = auto_action {
						auto_value
					}
					else {
						let answer: YesNoAuto = user_interface.get_user_answer(&format!("{}\nDo you wish to delete this path?", err));
						if let YesNoAuto::Continued(auto_value) = answer {
							auto_action = Some(auto_value);
						}
						answer.get_yesno_val()
					};
					match answer {
						YesNo::Yes => delete_element(e_d_element),
						YesNo::No => new_list.push(e_d_element),
					}
				},
			}
		}
		let deleted_paths_length = old_list_len - new_list.len();
		if deleted_paths.len() != deleted_paths_length {
			panic!("Invalid amount of elements deleted.");
		}

		if !deleted_paths.is_empty() {
			let length_width = deleted_paths_length.to_string().chars().count();
			user_interface.send_message(&format!("Deleted paths, amount = {}", deleted_paths_length));
			for (index, deleted_path) in deleted_paths.iter().enumerate() {
				user_interface.send_message(&format!(
					"{:0width$} of {}: {}",
					index + 1,
					deleted_paths_length,
					deleted_path,
					width = length_width
				));
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
		let existing_paths: std::collections::HashSet<_> = self.element_list.iter().map(|e| e.get_path()).collect();
		let pending_hashing: Vec<_> = self
			.index(".", user_interface)?
			.into_iter()
			.filter(|string| !existing_paths.contains(string.as_str()))
			.collect();

		let mut errors: Vec<CreateError> = Vec::new();

		let pending_hashing_length = pending_hashing.len();
		let pending_hashing_length_width = pending_hashing_length.to_string().chars().count();
		for (i, string) in pending_hashing.into_iter().enumerate() {
			user_interface.send_message(&format!(
				"Hashing file {:0width$} of {} = {}",
				i + 1,
				pending_hashing_length,
				string,
				width = pending_hashing_length_width
			));
			match EDElement::from_path(string) {
				Ok(new_element) => self.add_e_d_element(new_element),
				Err(err) => errors.push(err.into()),
			};
		}

		Ok(errors)
	}

	/// Sort this EDList according to the paths of the EDElements.
	pub fn sort(&mut self) {
		use std::cmp::Ordering;
		self.element_list.par_sort_unstable_by(|a: &EDElement, b: &EDElement| {
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
			else {
				cmp_state
			}
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
		let mut link_dups: HashMap<&str, Vec<&EDElement>> = HashMap::with_capacity(self.element_list.len());
		let mut file_dups: HashMap<Checksum, Vec<&EDElement>> = HashMap::with_capacity(self.element_list.len());
		for element in &self.element_list {
			match element.get_variant() {
				e_d_element::EDVariantFields::File { checksum } => match file_dups.entry(*checksum) {
					Entry::Occupied(entry) => entry.into_mut().push(element),
					Entry::Vacant(entry) => {
						entry.insert(vec![element]);
					},
				},
				e_d_element::EDVariantFields::Link { target } => match link_dups.entry(target) {
					Entry::Occupied(entry) => entry.into_mut().push(element),
					Entry::Vacant(entry) => {
						entry.insert(vec![element]);
					},
				},
			}
		}

		let mut collision_blocks = 0;
		user_interface.send_message("Links with same target path and origin directory:");
		link_dups.iter().filter(|(_, v)| v.len() > 1).for_each(|(key, vector)| {
			collision_blocks += 1;
			user_interface.send_message(&format!("{:4}links with target path = \"{}\":", "", key));
			for element in vector {
				user_interface.send_message(&format!("{:8}{}", "", element.get_path()));
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
		user_interface.send_message(&format!("{} unique collisions found", collision_blocks));
	}

	/// Returns a complete list of all files
	/// from the given root directory.
	/// Does not follow symbolic links, but symbolic links are indexed
	/// as a normal file.
	///
	/// Does not index if, file is not a regular readable file, or a symbolic link.
	/// Does not index paths that are in the banlist.
	fn index(&self, path: &str, interfacer: &impl UserInterface) -> Result<Vec<String>, IndexError> {
		let entries = std::fs::read_dir(path).map_err(|err| IndexError::CantGetSubDirError(path.to_string(), err.to_string()))?;
		let mut index_list: Vec<String> = Vec::new();

		for entry in entries {
			let entry = entry?;
			let file_type = entry.file_type()?;

			let file_path = format!(
				"{}/{}",
				path,
				entry.file_name().into_string().map_err(|_| IndexError::OsStringConvertError(path.to_string()))?
			);
			// If file_path is in banlist, we should not index it.
			if self.banlist.is_in_banlist(&file_path) {
				continue;
			}
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
						"The file \"{}\" is neither a readable file, a symbolic link or a directory, and was skipped during file indexing.",
						file_path
					)
					.as_ref(),
				);
			}
		}
		Ok(index_list)
	}

	fn get_version_from_line(line: &str) -> ListVersion {
		match line.strip_prefix(LIST_VERSION_PREFIX) {
			Some("1.1") => ListVersion::V1_1,
			Some("1.0") => ListVersion::V1_0,
			Some(identifier) => ListVersion::InvalidVersion(identifier),
			None => ListVersion::MissingIdentifier,
		}
	}

	/// This is the only method that must be used to add elements
	/// to the EDList after it is initialized.
	/// It handles updating the lists internal xor checksum.
	fn add_e_d_element(&mut self, element: EDElement) {
		self.xor_checksum ^= element.get_hash();
		self.element_list.push(element);
	}

	/// Write EDList to {root_path}/file_hasher_files/file_hashes
	pub fn write_hash_file(&self) -> Result<(), WriteHashFileError> {
		let mut file = File::create(format!("{}/file_hasher_files/file_hashes", self.root_path))
			.map_err(|err| WriteHashFileError::ErrorCreatingFile(err.to_string()))?;
		self.write_edlist_to_file(&mut file, "file_hashes")?;
		Ok(())
	}

	fn write_backup(&self) -> Result<(), WriteBackupError> {
		let backup_dir = format!("{}/file_hasher_files/hash_file_backups", self.root_path);
		create_dir_all(&backup_dir).map_err(|err| WriteBackupError::CreateDirectoryError(err.to_string()))?;
		let local: DateTime<Local> = Local::now();
		let mut file = File::create(format!("{}/{}", backup_dir, local.format("%Y-%m-%d %H.%M.%S.%f %z")))
			.map_err(|err| WriteBackupError::CreateFileError(err.to_string()))?;
		self.write_edlist_to_file(&mut file, "hashbackup")?;
		Ok(())
	}

	/// Used when we need to write hash_file data to a file
	/// Also used for writing the backups to file.
	fn write_edlist_to_file(&self, file: &mut File, file_name: &str) -> Result<(), WriteEDListToFileError> {
		let mut hasher = Blake2bVar::new(HASH_OUTPUT_LENGTH).unwrap();
		let mut element_string = String::new();

		for element in &self.element_list {
			element_string.push_str(format!("{}\n", element).as_ref());
			hasher.update(element.get_hash().as_ref());
		}
		hasher.update(self.xor_checksum.as_ref());

		let list_version_string = format!("{}{}\n", LIST_VERSION_PREFIX, CURRENT_LIST_VERSION);
		let xor_checksum_string = format!("{}{}\n", XOR_CHECKSUM_PREFIX, hex::encode_upper(&self.xor_checksum.as_ref()));
		let fin_checksum_string = format!("{}{}\n", FIN_CHECKSUM_PREFIX, shared::blake2_to_checksum(hasher));

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
		let SlashEnding { path: relative_path } = user_interface.get_user_answer("Enter the relative path:");

		if let Some(hash) = self.internal_relative_checksum(relative_path.as_str(), false) {
			user_interface.send_message(&format!("Relative hash:\n{}", hash));
		}
		else {
			user_interface.send_message("No files were found in the specified path");
		}
	}

	fn internal_relative_checksum(&self, relative_path: &str, no_elements_allowed: bool) -> Option<Checksum> {
		let mut hasher = Blake2bVar::new(HASH_OUTPUT_LENGTH).unwrap();
		let mut elements_found = false;
		self.element_list
			.iter()
			.filter_map(|e_d_element| try_join!(Some(e_d_element), e_d_element.get_path().strip_prefix(relative_path)))
			.for_each(|(e_d_element, postfix)| {
				elements_found = true;
				hasher.update(postfix.as_bytes());
				hasher.update(&e_d_element.get_modified_time().to_le_bytes());
				match e_d_element.get_variant() {
					e_d_element::EDVariantFields::File { checksum } => hasher.update(checksum.as_ref()),
					e_d_element::EDVariantFields::Link { target } => hasher.update(target.as_bytes()),
				}
			});
		if elements_found || no_elements_allowed { Some(shared::blake2_to_checksum(hasher)) } else { None }
	}

	fn internal_negated_relative_checksum(&self, relative_path: &str) -> Checksum {
		let mut hasher = Blake2bVar::new(HASH_OUTPUT_LENGTH).unwrap();
		self.element_list
			.iter()
			.filter(|e_d_element| e_d_element.get_path().strip_prefix(relative_path).is_none())
			.for_each(|e_d_element| {
				hasher.update(e_d_element.get_path().as_bytes());
				hasher.update(&e_d_element.get_modified_time().to_le_bytes());
				match e_d_element.get_variant() {
					e_d_element::EDVariantFields::File { checksum } => hasher.update(checksum.as_ref()),
					e_d_element::EDVariantFields::Link { target } => hasher.update(target.as_bytes()),
				}
			});
		shared::blake2_to_checksum(hasher)
	}

	/// Deletes all empty folders within the given root directory.
	///
	/// Ignores folders that is in the given banlist.
	///
	/// Also tells the user through user_interface, which folders were deleted.
	fn delete_empty_folders(path: &Path, banlist: &PathBanlist, user_interface: &impl UserInterface) -> Result<bool, SyncFromError> {
		let mut files_or_banlist_found = false;

		for entry in std::fs::read_dir(path)? {
			let entry_path = entry?.path();
			if entry_path.is_dir() &&
				!banlist.is_in_banlist(&format!("{}/", entry_path.to_str().expect("Folders with non utf-8 names is not supported!")))
			{
				files_or_banlist_found = EDList::delete_empty_folders(&entry_path, banlist, user_interface)? || files_or_banlist_found;
			}
			else {
				files_or_banlist_found = true;
			}
		}
		if !files_or_banlist_found {
			user_interface.send_message(&format!("Deleting folder {}", path.to_str().unwrap()));
			std::fs::remove_dir(path)?;
		}
		Ok(files_or_banlist_found)
	}

	/// Executes a list of IO Fileoperations.
	///
	/// This operation modifies the real Filesystem, so use with care.
	fn do_file_operations(
		operations: &[FileOperation], user_interface: &impl UserInterface, backup_folder: &str,
	) -> Result<(), SyncFromError> {
		use std::fs;

		use filetime::{set_symlink_file_times, FileTime};
		use FileOperation::*;

		let operations_length_width = operations.len().to_string().len();
		let mut synclist = fs::OpenOptions::new()
			.create(true)
			.write(true)
			.append(true)
			.open(format!("{}synclist", backup_folder))?;
		for operation in operations {
			let op_string = format!("{}\n", operation);
			synclist.write_all(op_string.as_bytes())?;
		}

		for (i, operation) in operations.iter().enumerate() {
			user_interface.send_message(&format!(
				"operation {:0width$} of {}: {}",
				i + 1,
				operations.len(),
				operation,
				width = operations_length_width
			));
			match operation {
				Delete(path) => {
					fs::create_dir_all(format!("{}{}", &backup_folder, Path::new(path).parent().unwrap().to_str().unwrap()))?;
					fs::rename(path, format!("{}{}", &backup_folder, path))?;
				},
				Move { from, to } => {
					let dir = Path::new(to).parent().ok_or(SyncFromError::GetPathParentError)?;
					fs::create_dir_all(dir)?;
					fs::rename(from, to)?;
				},
				Copy { from, to } => {
					let dir = Path::new(to).parent().ok_or(SyncFromError::GetPathParentError)?;
					fs::create_dir_all(dir)?;
					let metadata = fs::symlink_metadata(from)?;
					if metadata.is_file() {
						std::fs::copy(from, to)?;
					}
					else {
						match fs::read_link(from).unwrap().to_str() {
							Some(link_path) => {
								// Create new symbolic link. Won't work on Windows.
								#[cfg(unix)]
								std::os::unix::fs::symlink(link_path, to)?;
								#[cfg(windows)]
								user_interface.send_message(&format!(
									"Error cloning symbolic link '{}', Symbolic links in Windows are unsupported.",
									link_path
								));
							},
							None => Err(SyncFromError::InvalidUtf8Link(from.into()))?,
						}
					}
					let modified_time = FileTime::from_last_modification_time(&metadata);
					let created_time = FileTime::from_creation_time(&metadata).unwrap_or_else(FileTime::now);
					set_symlink_file_times(to, created_time, modified_time)?;
				},
			}
		}
		Ok(())
	}

	/// Attempts to syncronise another EDLists relative path to the currents relative path
	/// as given by the user.
	pub fn sync(&mut self, user_interface: &impl UserInterface) -> Result<(), SyncFromError> {
		use std::mem;

		use itertools::{Either, Itertools};

		user_interface.send_message(
			"Warning, this operation can be dangerous to your target directory.\nShould an issue occur the file_hashes list will be \
			 backed up in the file_hasher_files directory.\nDeleted files and information about actions done will be placed here as \
			 well.\nThis also doesn't copy the banlist of the source list.",
		);

		let SlashEnding { path: source_folder_path } = user_interface.get_user_answer("Enter path to other folder indexed by file_hasher:");
		let mut source_e_d_list = EDList::open(&source_folder_path, &StubUserInterface::new("NO".to_string()), PathBanlist::new_dummy())?;
		let SlashEnding { path: sync_to_prefix } =
			user_interface.get_user_answer("Enter relative path from the current edlist, where you will sync to:");
		let SlashEnding { path: sync_from_prefix } =
			user_interface.get_user_answer("Enter relative path from the external edlist, where you will sync from");

		std::fs::create_dir_all(&sync_to_prefix)?;
		let user_answer: YesNo = user_interface.get_user_answer(&format!(
			"Sync from {:?} -> {:?}.\nIs this ok?",
			canonicalize(format!("{}{}", source_folder_path, sync_from_prefix))?,
			canonicalize(&sync_to_prefix)?
		));
		if user_answer == YesNo::No {
			return Err(SyncFromError::UserAbort);
		}
		let target_element_list_backup = self.element_list.clone();
		let target_xor_checksum_backup = self.xor_checksum;

		let source_relative_checksum = source_e_d_list.internal_relative_checksum(sync_from_prefix.as_str(), true).unwrap();
		let target_negated_relative_checksum = self.internal_negated_relative_checksum(sync_to_prefix.as_str());

		let (target_list, existing_files_vec): (Vec<_>, Vec<_>) = mem::take(&mut self.element_list).into_iter().partition_map(|element| {
			if element.get_path().strip_prefix(sync_to_prefix.as_str()).is_some() {
				self.xor_checksum ^= element.get_hash();
				Either::Right(element)
			}
			else {
				Either::Left(element)
			}
		});
		self.element_list = target_list;

		let mut existing_files_map = existing_files_vec.into_iter().fold(HashMap::new(), |mut map: HashMap<_, Vec<_>>, element| {
			map.entry((element.get_variant().clone(), element.get_modified_time())).or_default().push(element);
			map
		});

		let source_iter = mem::take(&mut source_e_d_list.element_list)
			.into_iter()
			.filter(|element| element.get_path().strip_prefix(sync_from_prefix.as_str()).is_some());

		let mut pre_file_operations = Vec::new(); // Moving files before they can be overwritten.
		let mut post_file_operations = Vec::new();
		let mut files_moved = false;
		source_iter.for_each(|mut source_element| {
			let mut empty_dummy_vec = Vec::new();
			let existing_files = existing_files_map
				.get_mut(&(source_element.get_variant().clone(), source_element.get_modified_time()))
				.unwrap_or(&mut empty_dummy_vec);
			let exact_match = existing_files
				.drain_filter(|existing_element| {
					let prefix_stripped_source = source_element.get_path().strip_prefix(sync_from_prefix.as_str()).unwrap();
					let prefix_stripped_target = existing_element.get_path().strip_prefix(sync_to_prefix.as_str()).unwrap();
					// Since paths are unique, there can only be up to one collision.
					prefix_stripped_source == prefix_stripped_target
				})
				.next();
			if let Some(exact_match) = exact_match {
				self.add_e_d_element(exact_match);
			}
			else {
				let prefix_stripped_source = source_element.get_path().strip_prefix(sync_from_prefix.as_str()).unwrap();
				let dest_path = format!("{}{}", sync_to_prefix, prefix_stripped_source);
				if let Some(mut existing_element) = existing_files.pop() {
					// File exists in target list, but has a different path.
					// Move file
					files_moved = true;
					let temp_path = format!("{}{}", TMPCOPYDIR, prefix_stripped_source);
					pre_file_operations.push(FileOperation::Move { from: existing_element.get_path().into(), to: temp_path.clone() });
					post_file_operations.push(FileOperation::Move { from: temp_path, to: dest_path.clone() });
					// Modify element
					existing_element.update_path(dest_path);
					self.add_e_d_element(existing_element);
				}
				else {
					// Element doesn't exist in target list.
					// Copy file
					post_file_operations.push(FileOperation::Copy {
						from: format!("{}{}", source_folder_path, source_element.get_path()),
						to:   dest_path.clone(),
					});
					source_element.update_path(dest_path);
					self.add_e_d_element(source_element);
				}
			}
		});

		// Delete all files left in existing files...
		existing_files_map.drain().flat_map(|(_, value)| value).for_each(|element| {
			pre_file_operations.push(FileOperation::Delete(element.take_path()));
		});

		let target_relative_checksum = self.internal_relative_checksum(sync_to_prefix.as_str(), true).unwrap();
		let new_target_negated_relative_checksum = self.internal_negated_relative_checksum(sync_to_prefix.as_str());

		if source_relative_checksum != target_relative_checksum || new_target_negated_relative_checksum != target_negated_relative_checksum
		{
			return Err(SyncFromError::ChecksumValidationError {
				source_rel:      source_relative_checksum,
				target_rel:      target_relative_checksum,
				new_negated_rel: new_target_negated_relative_checksum,
				negated_rel:     target_negated_relative_checksum,
			});
		}

		user_interface.send_message("These operations will be done:");
		let print_operation = |operation: &FileOperation| user_interface.send_message(&operation.to_string());
		pre_file_operations.iter().for_each(print_operation);
		post_file_operations.iter().for_each(print_operation);

		if user_interface.get_user_answer::<YesNo>("Do you want to continue?") == YesNo::No {
			self.element_list = target_element_list_backup;
			self.xor_checksum = target_xor_checksum_backup;
			return Err(SyncFromError::UserAbort);
		}

		let backup_folder = format!("./file_hasher_files/hash_file_backups/syncbackup-{}/", Local::now());
		std::fs::create_dir_all(&backup_folder)?;

		EDList::do_file_operations(&pre_file_operations, user_interface, &backup_folder)?;
		EDList::delete_empty_folders(Path::new("./"), &self.banlist, user_interface)?;
		EDList::do_file_operations(&post_file_operations, user_interface, &backup_folder)?;
		EDList::delete_empty_folders(Path::new("./"), &self.banlist, user_interface)?;
		if files_moved {
			EDList::delete_empty_folders(Path::new(TMPCOPYDIR), &PathBanlist::new_dummy(), user_interface)?;
		}
		Ok(())
	}

	/// Performs a benchmark of the hashing performance of the computer
	/// running it.
	///
	/// Will not modify the contents of the EDList at all.
	pub fn benchmark(user_interface: &impl UserInterface, bytes: usize) {
		struct ReadMock {
			bytes_left: usize,
		}
		impl std::io::prelude::Read for ReadMock {
			fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
				if self.bytes_left > buf.len() {
					self.bytes_left -= buf.len();
					Ok(buf.len())
				}
				else {
					self.bytes_left = 0;
					Ok(self.bytes_left)
				}
			}
		}

		let mut mock_file = ReadMock { bytes_left: bytes };
		user_interface.send_message("Now benchmarking...");

		let before = std::time::Instant::now();
		let checksum = EDElement::hash_file(&mut mock_file).unwrap();
		let time_elapsed_sec = before.elapsed().as_secs_f64();

		user_interface.send_message(&format!("resulting hash = {}", checksum));

		let units = ["Bytes", "KiB", "MiB", "GiB"];

		let mut cur_unit_over_time = bytes as f64 / time_elapsed_sec;

		let length = format!("{:.2}", cur_unit_over_time).len();
		let mut longest = 0;
		for unit in units.iter() {
			let result = format!("|{: <width$.2} {: <width2$} hashed a second|", cur_unit_over_time, unit, width = length, width2 = 5);
			longest = longest.max(result.len());
			user_interface.send_message(&format!("|{:-<width$}|", "", width = longest - 2));
			user_interface.send_message(&result);
			cur_unit_over_time /= 1024f64;
		}
		user_interface.send_message(&format!("|{:-<width$}|", "", width = longest - 2));
	}
}
