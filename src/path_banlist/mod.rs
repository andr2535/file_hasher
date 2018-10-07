extern crate blake2;

use std::{fs::{File, create_dir_all}, io::{BufRead, BufReader, Write}, collections::HashSet};
use self::blake2::{Blake2b, digest::{Input, VariableOutput}};

const CHECKSUM_PREFIX:&str = "CHECKSUM = ";
const HASH_OUTPUT_LENGTH:usize = 32;

enum LineType {
	Comment,
	Checksum(String),
	BannedPath
}

#[derive(Debug)]
pub struct PathBanlist {
	banned_paths:HashSet<String>
}
impl PathBanlist {
	pub fn open() -> Result<PathBanlist, String> {
		let file = match File::open("./file_hasher_files/banlist") {
			Ok(file) => file,
			Err(err) => return Result::Err(format!("banlist file could not be opened, error message = {}", err))
		};
		let buf_reader = BufReader::new(file);
		
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		let mut checksum: Option<String> = Option::None;
		let mut banned_paths: HashSet<String> = HashSet::new();

		for line in buf_reader.lines() {
			let line = match line {
				Ok(line) => line,
				Err(err) => return Result::Err(String::from(format!("Error reading line, error message = {}", err)))
			};
			
			match PathBanlist::identify_line(&line) {
				LineType::BannedPath => {
					hasher.process(line.as_bytes());
					banned_paths.insert(line);
				},
				LineType::Checksum(value) => {
					match checksum {
						None => {
							checksum = Some(value);
						},
						Some(_val) => {
							return Err(String::from("More than one checksum in banlist, remove the redundant ones!"));
						}
					}
				}
				LineType::Comment => () // Comments are not important to the integrity of the file...
			}
		}

		// Verify checksum validiy against the generated hash.
		let hash_string = PathBanlist::blake2_to_string(hasher);
		match checksum {
			Some(checksum) => {
				if hash_string != checksum {
					return Err(format!("Checksum for banlist is invalid.\n\
					                    If the current banlist is correct,\nReplace the checksum in the banlist file with the following:\n\
					                    {}{}", CHECKSUM_PREFIX, hash_string));
				}
			},
			None => {
					return Err(format!("There is no checksum in the banlist file.\n\
					                    If the current banlist is correct,\nType the following line into the banlist file:\n\
					                    {}{}", CHECKSUM_PREFIX, hash_string));
			}
		}

		return Result::Ok(PathBanlist{banned_paths});
	}
	pub fn new() -> Result<PathBanlist, String> {
		match create_dir_all("./file_hasher_files") {
			Ok(_res) => (),
			Err(err) => return Err(format!("Error creating file_hasher directory, Error = {}", err))
		};
		
		let mut file = match File::create("./file_hasher_files/banlist") {
			Ok(file) => file,
			Err(err) => return Err(format!("Error creating file, Error = {}", err))
		};
		
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		let def_banned_list = ["./lost+found", "./.Trash-1000", "./file_hasher_files"];

		for string in def_banned_list.iter() {
			match file.write(format!("{}\n", string).as_bytes()) {
				Ok(_len) => (),
				Err(err) => return Err(format!("Error writing line to file, Error = {}", err))
			}
			hasher.process(string.as_bytes());
		}

		let write_result = file.write(format!("{}{}", CHECKSUM_PREFIX, PathBanlist::blake2_to_string(hasher)).as_bytes());

		match write_result {
			Ok(_len) => {
				return PathBanlist::open();
			}
			Err(err) => return Err(format!("Error writing checksum to banlist, Error = {}", err))
		};
	}

	fn blake2_to_string(hasher:Blake2b) -> String {
		let mut hash = [0u8; HASH_OUTPUT_LENGTH];
		hasher.variable_result(&mut hash).unwrap();

		let mut hash_string = String::with_capacity(HASH_OUTPUT_LENGTH*2);
		for byte in hash.iter() {
			hash_string.push_str(&format!("{:X}", byte));
		}

		return hash_string;
	}

	fn identify_line(line: &String) -> LineType {
		let checksum_prefix = String::from(CHECKSUM_PREFIX);

		match line.chars().next() {
			Some(character) => 
				if character == '#' {
					return LineType::Comment;
				},
			// If the string is empty, it has function like a comment.
			None => return LineType::Comment
		};
		if line.len() >= checksum_prefix.len() && checksum_prefix == line[0..checksum_prefix.len()] {
			return LineType::Checksum(String::from(&line[checksum_prefix.len()..line.len()]));
		}
		LineType::BannedPath
	}
}