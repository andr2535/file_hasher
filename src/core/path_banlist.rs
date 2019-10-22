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

use std::{fs::{File, create_dir_all}, io::{BufRead, BufReader, Write}, collections::HashMap};
use blake2::{Blake2b, digest::{Input, VariableOutput}};
use crate::interfacer::UserInterface;
use super::constants;
use super::shared;

enum LineType {
	Comment,
	Checksum(String),
	BannedPath
}

#[derive(Debug)]
enum CharMapper {
	Terminator,
	More(HashMap<char, CharMapper>)
}

/// PathBanlist is a HashSet that contains all the paths that
/// should not be hashed by the EDList objects.
#[derive(Debug)]
pub struct PathBanlist {
	banned_paths:HashMap<char, CharMapper>
}
impl PathBanlist {
	/// Requires an object implementing the trait UserInterface also defined in 
	/// this file.
	/// Attempts to open the banlist file from ./file_hasher_files/banlist
	/// May use the given object implementing UserInterface, to ask the user to
	/// give input if an issue arises.
	/// If attempts go wrong, the funtion will return a string, with a
	/// description of the problem.
	pub fn open(banlist_interfacer: impl UserInterface) -> Result<PathBanlist, String> {
		let file = match File::open("./file_hasher_files/banlist") {
			Ok(file) => file,
			Err(err) => {
				loop {
					let create_new = banlist_interfacer.get_user_answer(
					    &format!("banlist file could not be opened, error message = {}\
					    \nDo you wish to create a new banlist? YES/NO", err));
					if create_new == "YES" {
						match PathBanlist::new(banlist_interfacer) {
							Ok(banlist) => return Ok(banlist),
							Err(err) => return Err(err)
						}
					}
					else if create_new == "NO" {return Err("banlist file could not be opened".to_string());}
				}
			}
		};
		let buf_reader = BufReader::new(file);
		
		let mut hasher = Blake2b::new(constants::HASH_OUTPUT_LENGTH).unwrap();
		let mut checksum: Option<String> = Option::None;
		let mut banned_paths: HashMap<char, CharMapper> = HashMap::new();

		for line in buf_reader.lines() {
			let line = match line {
				Ok(line) => line,
				Err(err) => return Err(format!("Error reading line, error message = {}", err))
			};
			
			match PathBanlist::identify_line(&line) {
				LineType::BannedPath => {
					hasher.process(line.as_bytes());

					PathBanlist::insert_to_banlist(line.chars(), &mut banned_paths);
				},
				LineType::Checksum(value) => {
					match checksum {
						None => {
							checksum = Some(value);
						},
						Some(_val) => {
							return Err("More than one checksum in banlist, remove the redundant ones!".to_string());
						}
					}
				}
				LineType::Comment => () // Comments are not important to the integrity of the file...
			}
		}

		// Verify checksum validiy against the generated hash.
		let hash_string = shared::blake2_to_string(hasher);
		match checksum {
			Some(checksum) => {
				if hash_string != checksum {
					return Err(format!("Checksum for banlist is invalid.\n\
					                    If the current banlist is correct,\nReplace the checksum in the banlist file with the following:\n\
					                    {}{}", constants::FIN_CHECKSUM_PREFIX, hash_string));
				}
			},
			None => {
					return Err(format!("There is no checksum in the banlist file.\n\
					                    If the current banlist is correct,\nType the following line into the banlist file:\n\
					                    {}{}", constants::FIN_CHECKSUM_PREFIX, hash_string));
			}
		}

		Ok(PathBanlist{banned_paths})
	}
	/// Attempts to create a new banlist file, and then opens it using
	/// the open function.
	/// Requires a object that implements UserInterface, so that it can send it
	/// on to the open function.
	/// When it fails, it returns a string containing information about
	/// the error.
	fn new(banlist_interfacer: impl UserInterface) -> Result<PathBanlist, String> {
		match create_dir_all("./file_hasher_files") {
			Ok(()) => (),
			Err(err) => return Err(format!("Error creating file_hasher directory, Error = {}", err))
		};
		
		let mut file = match File::create("./file_hasher_files/banlist") {
			Ok(file) => file,
			Err(err) => return Err(format!("Error creating file, Error = {}", err))
		};
		
		let mut hasher = Blake2b::new(constants::HASH_OUTPUT_LENGTH).unwrap();
		let def_banned_list = ["./lost+found/", "./.Trash-1000/", "./file_hasher_files/"];

		for string in def_banned_list.iter() {
			match file.write(format!("{}\n", string).as_bytes()) {
				Ok(_len) => (),
				Err(err) => return Err(format!("Error writing line to file, Error = {}", err))
			}
			hasher.process(string.as_bytes());
		}

		let write_result = file.write(format!("{}{}", constants::FIN_CHECKSUM_PREFIX, shared::blake2_to_string(hasher)).as_bytes());

		match write_result {
			Ok(_len) => PathBanlist::open(banlist_interfacer),
			Err(err) => Err(format!("Error writing checksum to banlist, Error = {}", err))
		}
	}

	/// identify_line determines if a line is a comment, a checksum or a banned path.
	fn identify_line(line: &str) -> LineType {
		match line.chars().next() {
			Some(character) => 
				if character == '#' {
					return LineType::Comment;
				},
			// If the string is empty, it has function like a comment.
			None => return LineType::Comment
		};

		// Figure out whether line is a checksum.
		let checksum_prefix_u8 = constants::FIN_CHECKSUM_PREFIX.as_bytes();
		let line_checksum_u8 = line.as_bytes();

		if line_checksum_u8.len() >= checksum_prefix_u8.len() && 
		   checksum_prefix_u8 == &line_checksum_u8[..checksum_prefix_u8.len()] {
			return LineType::Checksum(String::from(&line[checksum_prefix_u8.len()..]));
		}

		// If line is not identified as a comment or a checksum, it must be a bannedpath.
		LineType::BannedPath
	}
	
	/// Used internally by the path_banlist open constructor,
	/// to insert the needed paths into the banlist.
	/// 
	/// The returned value should be ignored by the caller,
	/// unless the caller is also insert_to_banlist.
	fn insert_to_banlist(mut char_iter: std::str::Chars, hashmap: &mut HashMap<char, CharMapper>) -> Option<CharMapper> {
		let character = match char_iter.next() {
			Some(character) => character,
			// If line is ended, we make the calling insert_to_banlist
			// insert a Terminator.
			None => return Some(CharMapper::Terminator)
		};

		let new_char_mapper = match hashmap.get_mut(&character) {
			// If there is already an inner hashmap,
			// we will insert the rest of the string into it.
			Some(CharMapper::More(inner_hashmap)) => PathBanlist::insert_to_banlist(char_iter, inner_hashmap),
			// If we hit a terminator, we do not need to continue,
			// since a prefix of the string is already terminating
			Some(CharMapper::Terminator) => None,
			// If there is none, we must create a new hashmap,
			// and place it according to our chars value.
			None => {
				let mut new_hashmap = HashMap::new();
				// Insert the remaining letters into the newly created hashmap recursively.
				match PathBanlist::insert_to_banlist(char_iter, &mut new_hashmap) {
					Some(char_mapper) => Some(char_mapper),
					None => Some(CharMapper::More(new_hashmap))
				}
			}
		};
		
		// Because we build the hashmap from the inside, we will
		// take the returned CharMapper(if any) from the recursive call
		// and insert it into the character position in the given hashmap.
		if let Some(new_char_mapper) = new_char_mapper {
			hashmap.insert(character, new_char_mapper);
		}
		None
	}
	
	/// Used to test whether the given path has any
	/// of its prefixes defined in the banlist.
	/// Returns true, if there is such a prefix, else it
	/// returns false.
	pub fn is_in_banlist(&self, path: &str) -> bool {
		let mut hashmap = &self.banned_paths;
		for character in path.chars() {
			match hashmap.get(&character) {
				Some(CharMapper::More(next_map)) => hashmap = next_map,
				Some(CharMapper::Terminator) => return true,
				None => return false
			}
		}
		false
	}
}