extern crate chrono;
extern crate blake2;

pub mod e_d_element;

use self::e_d_element::EDElement;
use self::path_banlist::PathBanlist;
use super::*;
use self::chrono::prelude::*;
use self::blake2::{Blake2b, digest::{Input, VariableOutput}};
use std::{fs::{File, create_dir_all}, io::{BufRead, BufReader, Write}};
use interfacers::UserInterface;

const CHECKSUM_PREFIX:&str = "CHECKSUM = ";
const HASH_OUTPUT_LENGTH: usize = 32;

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
pub struct EDList {
	element_list: Vec<EDElement>,
	banlist: path_banlist::PathBanlist,
	checksum: [u8; HASH_OUTPUT_LENGTH]
}
impl EDList {
	/// Attempts to open the ./file_hasher_files/file_hashes file
	/// and interprets it as an EDList.
	/// If it is unable to open the file, it may ask the user
	/// whether it should create a new file, using an object implementing
	/// UserInterface.
	pub fn open(list_interface: impl UserInterface, banlist: PathBanlist) -> Result<EDList, String> {
		let mut e_d_list = EDList::new(banlist);
		let file = match File::open("./file_hasher_files/file_hashes") {
			Ok(file) => file,
			Err(err) => {
				loop{
					let answer = list_interface
						.get_user_answer(&format!("Could not open file_hashes, err = {}\nDo you wish to create a new file? YES/NO", err));
					if answer == "YES" {return Ok(e_d_list);}
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
			
			match EDList::identify_line(&line) {
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
				if checksum != PathBanlist::blake2_to_string(hasher) {
					return Err(String::from("checksum in file_hashes is not valid!"));
				}
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
		EDList{element_list: Vec::new(), banlist: banlist, checksum: [0u8; HASH_OUTPUT_LENGTH]}
	}

	/// Finds all the files that have not been
	/// added to the list yet, and puts them into the list.
	/// It gives messages of all the elements it is hashing
	/// to the list_interface, while it is in progress.
	pub fn create(&mut self, list_interface: impl UserInterface) -> Result<(), String> {
		let mut already_in_list = std::collections::HashSet::new();
		for element in &self.element_list {
			already_in_list.insert(element.get_path().clone());
		}

		let index_strings = match self.index(&String::from(".")) {
			Ok(strings) => strings,
			Err(err) => return Err(format!("Error indexing files, Err = {}", err))
		};

		let mut pending_hashing = Vec::new();
		for string in index_strings {
			if !already_in_list.contains(&string) {
				pending_hashing.push(string);
			}
		}

		let pending_hashing_length = pending_hashing.len();
		for (i, string) in pending_hashing.into_iter().enumerate() {
			list_interface.send_message(&format!("Hashing file {} of {} = {}", i+1, pending_hashing_length, string));
			let new_element = match EDElement::from_path(string) {
				Ok(new_element) => new_element,
				Err(err) => return Err(err)
			};
			self.add_e_d_element(new_element);
		}

		Ok(())
	}

	/// Returns a complete list of all files
	/// from the given root directory.
	/// Does not follow symbolic links, but symbolic links are indexed
	/// as a normal file.
	/// Does not index paths that are in the banlist.
	fn index(&self, path:&String) -> Result<Vec<String>, String> {
		let entries = match std::fs::read_dir(&path) {
			Ok(dirs) => dirs,
			Err(err) => return Err(format!("{}", err))
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

	fn identify_line(line: &String) -> LineType {
		let checksum_prefix = String::from(CHECKSUM_PREFIX);

		// Figure out whether line is a checksum.
		let mut line_checksum = String::with_capacity(checksum_prefix.len());
		for (checksum_char, line_char) in checksum_prefix.chars().zip(line.chars()) {
			if checksum_char == line_char {
				line_checksum.push(line_char);
			}
			else {break;}
		}
		// If line_checksum length has reached checksum_prefix length, we know that
		// line_checksum has the CHECKSUM_PREFIX as prefix.
		if checksum_prefix.len() == line_checksum.len() {
			return LineType::Checksum(String::from(&line[checksum_prefix.len()..line.len()]));
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
		let checksum_string = format!("{}{}", CHECKSUM_PREFIX, PathBanlist::blake2_to_string(hasher));
		match file.write(checksum_string.as_bytes()) {
			Ok(_len) => (),
			Err(err) => return Err(format!("Error writing checksum to the {}, err = {}", file_name, err))
		}
		Ok(())
	}
}