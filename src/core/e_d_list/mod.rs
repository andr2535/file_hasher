pub mod e_d_element;

use self::e_d_element::EDElement;
use super::shared;
use super::path_banlist::PathBanlist;
use crate::core::constants::{HASH_OUTPUT_LENGTH,CHECKSUM_PREFIX};

use chrono::prelude::{DateTime, Local};
use blake2::{Blake2b, digest::{Input, VariableOutput}};
use std::{fs::{File, create_dir_all}, io::{BufRead, BufReader, Write}, collections::HashMap};
use crate::interfacer::UserInterface;

enum LineType {
	Checksum(String),
	EDElement
}

#[derive(Debug)]
/// EDList is a list of all the files in a subdirectory
/// to the current directory, excepting the files that
/// lies under the paths that exists in the banlist.
///
/// The checksum is calculated by xoring the element_hash
/// of the EDElement files together, it is used together
/// with the EDElements to create a checksum that is saved
/// to the hashlist file.
///
/// The checksum will always be checked against the
/// saved checksum in the file, when loading the list from
/// file. Also the saved checksum is used in the memory,
/// such that it is very hard for a memory error to cause
/// data corruption in the file after a reload.
///
/// The verified boolean is used to be sure that
/// the checksum test went well(in case of the program counter
/// skipping or some case similar)
pub struct EDList {
	element_list: Vec<EDElement>,
	banlist: PathBanlist,
	checksum: [u8; HASH_OUTPUT_LENGTH],
	verified: bool
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
	pub fn open(list_interface: impl UserInterface, banlist: PathBanlist) -> Result<EDList, String> {
		let mut e_d_list = EDList::new(banlist);
		let file = match File::open("./file_hasher_files/file_hashes") {
			Ok(file) => file,
			Err(err) => {
				loop{
					let answer = list_interface
						.get_user_answer(&format!("Could not open file_hashes, err = {}\nDo you wish to create a new file? YES/NO", err));
					if answer == "YES" {
						list_interface.send_message("Created empty list");
						e_d_list.verified = true;
						return Ok(e_d_list);
					}
					else if answer == "NO" {break;}
				}
				return Err(String::from("Error opening file_hashes"));
			}
		};
		let buf_reader = BufReader::new(file);
		let mut checksum: Option<String> = Option::None;
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();

		for line in buf_reader.lines() {
			let line = match line {
				Ok(line) => line,
				Err(err) => return Result::Err(String::from(format!("Error reading line, error message = {}", err)))
			};
			
			match EDList::identify_line(line.as_ref()) {
				LineType::Checksum(value) => {
					match checksum {
						None => {
							checksum = Some(value);
						},
						Some(_val) => {
							return Err(String::from("More than one checksum in file_hashes!"));
						}
					}
				},
				LineType::EDElement => {
					let element = match EDElement::from_str(&line) {
						Ok(element) => element,
						Err(err) => return Err(format!("Error interpreting EDElement from file_hashes, line = {}, err = {}", line, err))
					};
					hasher.process(element.get_hash());
					e_d_list.add_e_d_element(element);
				}
			}
		}
		hasher.process(&e_d_list.checksum);
		
		match checksum {
			Some(checksum) => {
				let generated_checksum = shared::blake2_to_string(hasher);
				if checksum != generated_checksum {
					return Err(String::from("checksum in file_hashes is not valid!"));
				}
				e_d_list.verified = checksum == generated_checksum;
			}
			None => return Err(String::from("file_hashes missing checksum!"))
		}
		match e_d_list.write_backup() {
			Ok(_ok) => (),
			Err(err) => return Err(format!("Error writing backup, err = {}", err))
		}
		Ok(e_d_list)
	}
	/// Creates a new empty EDList.
	fn new(banlist: PathBanlist) -> EDList {
		EDList{element_list: Vec::new(), banlist: banlist, checksum: [0u8; HASH_OUTPUT_LENGTH], verified:false}
	}

	/// Tests every element in the lists integrity against
	/// the real files and links, they refer to.
	/// Returns a vector with strings describing all the errors.
	/// Also sends a message to the UserInterface impl, for every
	/// element that is being tested.
	pub fn verify(&self, prefix:Option<String>, list_interface: &impl UserInterface) -> Vec<String> {
		if !self.verified {panic!("EDList is not verified!");}
		match prefix {
			Some(prefix) => {
				let prefix_u8 = prefix.as_bytes();
				let element_list = &self.element_list;
				let mut elements_with_prefix:Vec<&EDElement> = Vec::with_capacity(element_list.len());
				for e_d_element in element_list {
					let path_u8 = e_d_element.get_path().as_bytes();
					if path_u8.len() >= prefix_u8.len() && &path_u8[0..prefix_u8.len()] == prefix_u8 {
						elements_with_prefix.push(e_d_element);
					}
				}
				self.verify_loop(&elements_with_prefix, list_interface)
			}
			None => self.verify_loop(&self.element_list, list_interface)
		}
	}

	/// Goes through all the elements in the given element_list.
	/// It returns a list of all the errors in a string format.
	fn verify_loop<T: AsRef<EDElement>>(&self, element_list: &[T], list_interface: &impl UserInterface) -> Vec<String> {
		let mut error_list = Vec::new();
		let mut file_count = 0;
		let list_length = element_list.len();
		let list_length_width = list_length.to_string().chars().count();

		for e_d_element in element_list {
			file_count += 1;
			let path = e_d_element.as_ref().get_path();
			list_interface.send_message(&format!("Verifying file {:0width$} of {} = {}", file_count, list_length, path, width=list_length_width));

			match e_d_element.as_ref().test_integrity() {
				Ok(_) => (),
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
	pub fn delete(&mut self, list_interface: &impl UserInterface) {
		if !self.verified {panic!("EDList is not verified!");}

		let old_list_len = self.element_list.len();
		let old_list = std::mem::replace(&mut self.element_list, Vec::with_capacity(old_list_len));
		let new_list = &mut self.element_list;

		let mut cont_delete = false;
		let mut deleted_paths:Vec<String> = Vec::new();

		let checksum = &mut self.checksum;
		let mut delete_element = |e_d_element:EDElement| {
			for (dest, hash_part) in checksum.iter_mut().zip(e_d_element.get_hash().iter()) {
				*dest ^= hash_part;
			}
			deleted_paths.push(e_d_element.take_path());
		};

		for e_d_element in old_list.into_iter() {
			let mut error = None;
			if self.banlist.is_in_banlist(e_d_element.get_path()) {
				error = Some(format!("Path {} is in the banlist", e_d_element.get_path()));
			}
			if error.is_none() {
				match e_d_element.test_metadata() {
					Ok(()) => (),
					Err(err) => error = Some(err)
				}
			}
			match error {
				None => {
					new_list.push(e_d_element);
				},
				Some(err) => {
					loop {
						if cont_delete {
							delete_element(e_d_element);
							break;
						}
						else {
							let answer = list_interface.get_user_answer(&format!("{}\nDo you wish to delete this path? YES/NO/CONTYES", err));
							match answer.as_str() {
								"YES" => {
									delete_element(e_d_element);
									break;
								},
								"NO" => {
									new_list.push(e_d_element);
									break;
								},
								"CONTYES" => {
									cont_delete = true;
									delete_element(e_d_element);
									break;
								}
								_ => ()
							}
						}
					}
				}
			}
		}
		if deleted_paths.len() > 0 {
			let length = deleted_paths.len();
			let length_width = length.to_string().chars().count();
			list_interface.send_message(&format!("Deleted paths, amount = {}", length));
			let mut index = 0;
			for deleted_path in deleted_paths {
				index += 1;
				list_interface.send_message(&format!("{:0width$} of {}: {}", index, length, deleted_path, width=length_width));
			}
		}
	}

	/// Finds all the files that have not been
	/// added to the list yet, and puts them into the list.
	/// It gives messages of all the elements it is hashing
	/// to the list_interface, while it is in progress.
	/// 
	/// In case of an error when reading the file_index_list,
	/// we return an error.
	/// 
	/// When this function returns Ok, it returns a list with
	/// all the errors created when trying to read files.
	pub fn create(&mut self, list_interface: &impl UserInterface) -> Result<Vec<String>, String> {
		if !self.verified {panic!("EDList is not verified!");}
		let mut pending_hashing = Vec::new();
		let mut existing_paths = std::collections::HashSet::with_capacity(self.element_list.len());
		for element in &self.element_list {
			existing_paths.insert(element.get_path());
		}

		let index_strings = match self.index(&String::from(".")) {
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
			list_interface.send_message(&format!("Hashing file {:0width$} of {} = {}", i+1,
			                            pending_hashing_length, string, width=pending_hashing_length_width));
			let new_element = match EDElement::from_path(string) {
				Ok(new_element) => new_element,
				Err(err) => {
					errors.push(err);
					continue;
				}
			};
			self.add_e_d_element(new_element);
		}

		Ok(errors)
	}

	/// Sort this EDList according to the paths of the EDElements.
	pub fn sort(&mut self) {
		if !self.verified {panic!("EDList is not verified!");}
		use std::cmp::Ordering;
		self.element_list.sort_unstable_by(|a:&EDElement,b:&EDElement| {
			let mut split_a = a.get_path().split('/');
			let mut split_b = b.get_path().split('/');

			let mut cmp_state = Ordering::Equal;
			
			let mut a_next = split_a.next();
			let mut b_next = split_b.next();
			loop {
				let a = match a_next {Some(a) => a, None => break};
				let b = match b_next {Some(b) => b, None => break};

				if cmp_state != Ordering::Equal {
					// If we get here then both are subdirectories, with different roots.
					return cmp_state;
				}
				let cmp = a.cmp(b);
				if cmp_state == Ordering::Equal {
					cmp_state = cmp;
				}
				
				a_next = split_a.next();
				b_next = split_b.next();
			}
			
			match a_next {
				Some(_block) => {
					// If we get here, then a has a next, but b doesn't
					return Ordering::Greater;
				},
				None => ()
			}
			match b_next {
				Some(_block) => {
					// If we get here, then b has a next, but a doesn't
					return Ordering::Less;
				},
				None => ()
			}
			cmp_state
		});
	}

	/// Sends a list of all the links that have the same
	/// link_target as at least one other link
	/// to the struct implementing UserInterface.
	/// 
	/// Also sends a list of all the files that have the
	/// same file_hash as at least one other file to the
	/// struct implementing UserInterface.
	pub fn find_duplicates(&self, list_interface: &impl UserInterface) {
		if !self.verified {panic!("EDList is not verified!");}
		use std::collections::hash_map::Entry;
		let mut link_dups:HashMap<&str, Vec<&EDElement>> = HashMap::with_capacity(self.element_list.len());
		let mut file_dups:HashMap<[u8; HASH_OUTPUT_LENGTH], Vec<&EDElement>> = HashMap::with_capacity(self.element_list.len());
		for element in &self.element_list {
			match element.get_variant() {
				e_d_element::EDVariantFields::File(file) => {
					match file_dups.entry(file.file_hash) {
						Entry::Occupied(entry) => {
							entry.into_mut().push(element);
						},
						Entry::Vacant(entry) => {
							entry.insert(vec!(element));
						}
					}
				},
				e_d_element::EDVariantFields::Link(link) => {
					match link_dups.entry(&link.link_target) {
						Entry::Occupied(entry) => {
							entry.into_mut().push(element);
						},
						Entry::Vacant(entry) => {
							entry.insert(vec!(element));
						}
					}
				}
			}
		}

		let mut collision_blocks = 0;
		list_interface.send_message("Links with same target path:");
		for (key, vector) in link_dups {
			if vector.len() <= 1 {continue;}
			collision_blocks += 1;
			list_interface.send_message(&format!("    links with target path \"{}\":", key));
			for element in vector {
				list_interface.send_message(&format!("        {}", element.get_path()));
			}
		}
		list_interface.send_message("Files with the same checksum:");
		for (hash, vector) in file_dups {
			if vector.len() <= 1 {continue;}
			collision_blocks += 1;
			let mut hash_str = String::with_capacity(HASH_OUTPUT_LENGTH*2);
			for byte in hash.iter() {
				hash_str += &format!("{:02X}", byte);
			}
			list_interface.send_message(&format!("    Files with checksum = \"{}\":", hash_str));
			for element in vector {
				list_interface.send_message(&format!("        {}", element.get_path()));
			}
		}
		list_interface.send_message(&format!("{} unique collisions found",collision_blocks));
	}

	/// Returns a complete list of all files
	/// from the given root directory.
	/// Does not follow symbolic links, but symbolic links are indexed
	/// as a normal file.
	/// Does not index paths that are in the banlist.
	fn index(&self, path:&String) -> Result<Vec<String>, String> {
		let entries = match std::fs::read_dir(&path) {
			Ok(dirs) => dirs,
			Err(err) => return Err(format!("Error getting subdirs from dir {}, error = {}", path, err))
		};
		let mut index_list:Vec<String> = Vec::new();
		
		for entry in entries {
			let (entry, file_type) = match entry {
				Ok(entry) => match entry.file_type() {
					Ok(file_type) => (entry, file_type),
					Err(_err) => return Err(String::from("Error getting file type of index"))
				},
				Err(_err) => return Err(String::from("Error iterating indexes"))
			};

			let file_path = match entry.file_name().into_string() {
				Ok(file_name) => format!("{}/{}", path, file_name),
				Err(_err) => return Err(format!("Failed to convert OsString to String in index"))
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
		return Ok(index_list);
	}

	/// Identifies a line as either a checksum, or an EDElement
	/// in String form.
	///
	/// Used to determine how the string should be processed.
	fn identify_line(line: &str) -> LineType {
		// Figure out whether line is a checksum.
		let checksum_prefix_u8 = CHECKSUM_PREFIX.as_bytes();
		let line_checksum_u8 = line.as_bytes();

		if line_checksum_u8.len() >= checksum_prefix_u8.len() && 
		   checksum_prefix_u8 == &line_checksum_u8[..checksum_prefix_u8.len()]{
			return LineType::Checksum(String::from(&line[checksum_prefix_u8.len()..line.len()]));
		}

		// If line is not identified as checksum it must be an EDElement.
		LineType::EDElement
	}

	/// This is the only method that must be used to add elements
	/// to the EDList.
	/// It handles updating the lists internal checksum.
	fn add_e_d_element(&mut self, element:EDElement) {
		for (dest, hash_part) in self.checksum.iter_mut().zip(element.get_hash().iter()) {
			*dest ^= *hash_part;
		}
		self.element_list.push(element);
	}

	pub fn write_hash_file(&self) -> Result<(), String> {
		let mut file = match File::create("./file_hasher_files/file_hashes") {
			Ok(file) => file,
			Err(err) => return Err(format!("Error creating file, Error = {}", err))
		};
		match self.write_to_file(&mut file, "file_hashes") {
			Ok(_ok) => (),
			Err(err) => return Err(err)
		}
		Ok(())
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

		match self.write_to_file(&mut file, "hashbackup") {
			Ok(_ok) => (),
			Err(err) => return Err(err)
		}
		Ok(())
	}

	/// Used when we need to write hash_file data to a file
	/// Also used for writing the backups to file.
	fn write_to_file(&self, file:&mut File, file_name:&str) -> Result<(), String> {
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();

		for element in &self.element_list {
			match file.write(format!("{}\n", element.to_string()).as_bytes()) {
				Ok(_len) => (),
				Err(err) => return Err(format!("Error writing to the {} file. err = {}", file_name, err))
			}
			hasher.process(element.get_hash());
		}
		hasher.process(&self.checksum);
		// We use the same conversion method as in PathBanlist, so we reuse it.
		let checksum_string = format!("{}{}", CHECKSUM_PREFIX, shared::blake2_to_string(hasher));
		match file.write(checksum_string.as_bytes()) {
			Ok(_len) => (),
			Err(err) => return Err(format!("Error writing checksum to the {}, err = {}", file_name, err))
		}
		Ok(())
	}
}