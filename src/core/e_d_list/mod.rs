pub mod e_d_element;

use self::e_d_element::EDElement;
use super::shared;
use super::path_banlist::PathBanlist;
use crate::core::constants::{HASH_OUTPUT_LENGTH,FIN_CHECKSUM_PREFIX, XOR_CHECKSUM_PREFIX};

use chrono::prelude::{DateTime, Local};
use blake2::{Blake2b, digest::{Input, VariableOutput}};
use std::{fs::{File, create_dir_all}, io::{BufRead, BufReader, Write}, collections::HashMap};
use crate::interfacer::UserInterface;

enum LineType {
	FinChecksum(String),
	XorChecksum(String),
	EDElement
}

#[derive(Debug)]
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
		let mut e_d_list = EDList::new(banlist);

		let buf_reader = BufReader::new(file);
		let mut final_checksum: Option<String> = None;
		let mut file_xor_checksum: Option<[u8;HASH_OUTPUT_LENGTH]> = None;
		let mut xor_checksum = [0u8;HASH_OUTPUT_LENGTH];
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();

		for line in buf_reader.lines() {
			let line = match line {
				Ok(line) => line,
				Err(err) => return Err(format!("Error reading line, error message = {}", err))
			};
			
			match EDList::identify_line(line.as_ref()) {
				LineType::FinChecksum(string) => {
					match final_checksum {
						None => final_checksum = Some(string),
						Some(_val) => return Err("More than one fin_checksum in file_hashes!".to_string())
					}
				},
				LineType::XorChecksum(string) => {
					match file_xor_checksum {
						None => {
							let mut new_xor_checksum = [0u8; HASH_OUTPUT_LENGTH];
							for (i, chunk) in string.as_bytes().chunks_exact(2).enumerate() {
								let chunk_str = match String::from_utf8(chunk.to_vec()) {
									Ok(chunk_str) => chunk_str,
									Err(_err) => return Err("Error in xor_checksum!".to_string())
								};
								match u8::from_str_radix(chunk_str.as_ref(), 16) {
									Ok(byte) => new_xor_checksum[i] = byte,
									Err(_err) => return Err("Error in xor_checksum!".to_string())
								}
							}
							file_xor_checksum = Some(new_xor_checksum);
						},
						Some(_val) => return Err("More than one xor_checksum in file_hashes!".to_string())
					}
				}
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
		if let Some(file_xor_checksum) = file_xor_checksum {
			if file_xor_checksum != xor_checksum {return Err("Saved xor_checksum is not valid".to_string());}
			hasher.process(&file_xor_checksum);

			e_d_list.xor_checksum = file_xor_checksum;
		}
		else {
			/// This function should make it hard for a single program counter
			/// corruption to introduce an invalid value into the EDList.
			/// 
			/// If the program should jump to this function it will not return a valid EDList,
			/// which would cause the program to probably not be able to terminate correctly.
			/// 
			/// Should the program finish anyway,
			/// the checksum of the EDList would nearly certainly be wrong.
			#[inline(never)]
			fn override_missing_xor_checksum(xor_checksum: &[u8;HASH_OUTPUT_LENGTH], e_d_list:&mut EDList, hasher: &mut Blake2b) {
				e_d_list.xor_checksum = *xor_checksum;
				hasher.process(xor_checksum);
			}
			loop {
				let answer = user_interface.get_user_answer("There was no xor_checksum in file_hashes.\
				                            \nDo you want to proceed with loading the file_hashes anyway? YES/NO");
				match answer.as_ref() {
					"YES" => {
						override_missing_xor_checksum(&xor_checksum, &mut e_d_list, &mut hasher);
						println!("Using hash file, even though the xor_checksum was not present!!!");
						break;
					},
					"NO" => return Err("No xor_checksum was found in file_hashes".to_string()),
					_ => ()
				}
			}
		};

		match final_checksum {
			Some(checksum) => {
				let generated_checksum = shared::blake2_to_string(hasher);
				if checksum != generated_checksum {
					return Err("checksum in file_hashes is not valid!".to_string());
				}
			}
			None => return Err("file_hashes missing checksum!".to_string())
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
				let prefix_u8 = prefix.as_bytes();
				let element_list = &self.element_list;
				let mut elements_with_prefix:Vec<&EDElement> = Vec::with_capacity(element_list.len());
				for e_d_element in element_list {
					let path_u8 = e_d_element.get_path().as_bytes();
					if path_u8.len() >= prefix_u8.len() && &path_u8[0..prefix_u8.len()] == prefix_u8 {
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

		let checksum = &mut self.xor_checksum;
		let mut delete_element = |e_d_element:EDElement| {
			for (dest, hash_part) in checksum.iter_mut().zip(e_d_element.get_hash().iter()) {
				*dest ^= *hash_part;
			}
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
				Some(err) => {
					loop {
						if cont_delete {
							delete_element(e_d_element);
							break;
						}
						else {
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
		if !deleted_paths.is_empty() {
			let length = deleted_paths.len();
			let length_width = length.to_string().chars().count();
			user_interface.send_message(&format!("Deleted paths, amount = {}", length));
			for (index, deleted_path) in deleted_paths.iter().enumerate() {
				user_interface.send_message(&format!("{:0width$} of {}: {}", index + 1, length, deleted_path, width=length_width));
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
				let cmp = a.cmp(b);
				if cmp_state == Ordering::Equal {
					cmp_state = cmp;
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
			let mut hash_str = String::with_capacity(HASH_OUTPUT_LENGTH*2);
			for byte in hash.iter() {
				hash_str += &format!("{:02X}", byte);
			}
			user_interface.send_message(&format!("{:4}Files with checksum = \"{}\":", "", hash_str));
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
				Err(_err) => return Err("Failed to convert OsString to String in index".to_string())
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


	fn chksum_cmp(prefix: &[u8], cmp_value: &[u8]) -> bool {
		cmp_value.len() >= prefix.len() && prefix == &cmp_value[..prefix.len()]
	}
	/// Identifies a line as either a checksum, or an EDElement
	/// in String form.
	///
	/// Used to determine how the string should be processed.
	fn identify_line(line: &str) -> LineType {
		// Figure out whether line is a checksum.
		let fin_checksum_prefix_u8 = FIN_CHECKSUM_PREFIX.as_bytes();
		let xor_checksum_prefix_u8 = XOR_CHECKSUM_PREFIX.as_bytes();
		let line_u8 = line.as_bytes();

		if EDList::chksum_cmp(fin_checksum_prefix_u8, line_u8) {
			LineType::FinChecksum(String::from(&line[fin_checksum_prefix_u8.len()..line.len()]))
		}
		else if EDList::chksum_cmp(xor_checksum_prefix_u8, line_u8) {
			LineType::XorChecksum(String::from(&line[xor_checksum_prefix_u8.len()..line.len()]))
		}
		// If line is not identified as either checksum variant it must be an EDElement.
		else {LineType::EDElement}
	}

	/// This is the only method that must be used to add elements
	/// to the EDList after it is initialized.
	/// It handles updating the lists internal checksum.
	fn add_e_d_element(&mut self, element:EDElement) {
		for (dest, hash_part) in self.xor_checksum.iter_mut().zip(element.get_hash().iter()) {
			*dest ^= *hash_part;
		}
		self.element_list.push(element);
	}

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

		for element in &self.element_list {
			match file.write_all(format!("{}\n", element.to_string()).as_bytes()) {
				Ok(_len) => (),
				Err(err) => return Err(format!("Error writing to the {} file. err = {}", file_name, err))
			}
			hasher.process(element.get_hash());
		}
		hasher.process(&self.xor_checksum);
		
		
		let xor_checksum_string = format!("{}{}\n", XOR_CHECKSUM_PREFIX, shared::hash_to_string(&self.xor_checksum));
		match file.write(xor_checksum_string.as_bytes()) {
			Ok(_len) => (),
			Err(err) => return Err(format!("Error writing xor_checksum to the {}, err = {}", file_name, err))
		}

		// We use the same conversion method as in PathBanlist, so we reuse it.
		let fin_checksum_string = format!("{}{}\n", FIN_CHECKSUM_PREFIX, shared::blake2_to_string(hasher));
		match file.write(fin_checksum_string.as_bytes()) {
			Ok(_len) => Ok(()),
			Err(err) => Err(format!("Error writing checksum to the {}, err = {}", file_name, err))
		}
	}
}