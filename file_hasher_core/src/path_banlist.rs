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
use blake2::{VarBlake2b, digest::{Update, VariableOutput}};
use crate::{shared, shared::UserInterface, shared::constants};

pub mod errors;
use errors::*;

enum LineType<'a> {
	Comment,
	Checksum(&'a str),
	BannedPath(&'a str)
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
	pub fn open(banlist_interfacer: &impl UserInterface) -> Result<PathBanlist, OpenPathBanlistError> {
		let file = match File::open("./file_hasher_files/banlist") {
			Ok(file) => file,
			Err(err) => {
				loop {
					let create_new = banlist_interfacer.get_user_answer(
					    &format!("banlist file could not be opened, error message = {}\
					    \nDo you wish to create a new banlist? YES/NO", err));
					if create_new == "YES" {
						PathBanlist::create()?;
						return PathBanlist::open(banlist_interfacer);
					}
					else if create_new == "NO" {return Err(OpenPathBanlistError::UserDeniedNewList);}
				}
			}
		};
		let buf_reader = BufReader::new(file);
		
		let mut hasher = VarBlake2b::new(constants::HASH_OUTPUT_LENGTH).unwrap();
		let mut file_checksum: Option<String> = Option::None;
		let mut banned_paths: HashMap<char, CharMapper> = HashMap::new();

		for line in buf_reader.lines() {
			match PathBanlist::identify_line(&line?) {
				LineType::BannedPath(line) => {
					hasher.update(line.as_bytes());

					PathBanlist::insert_to_banlist(line.chars(), &mut banned_paths);
				},
				LineType::Checksum(value) => {
					match file_checksum {
						None => file_checksum = Some(value.to_string()),
						Some(_val) => {
							return Err(OpenPathBanlistError::DuplicateChecksum);
						}
					}
				}
				LineType::Comment => () // Comments are not important to the integrity of the file...
			}
		}

		// Verify checksum validiy against the generated hash.
		let generated_checksum = shared::blake2_to_checksum(hasher);
		match file_checksum {
			Some(checksum) => {
				if generated_checksum.to_string() == checksum {Ok(PathBanlist{banned_paths})}
				else {Err(OpenPathBanlistError::InvalidChecksum(generated_checksum))}
			},
			None => {Err(OpenPathBanlistError::MissingChecksum(generated_checksum))}
		}
	}
	/// Attempts to create a new banlist file.
	/// Requires a object that implements UserInterface, so that it can send it
	/// on to the open function.
	/// When it fails, it returns a string containing information about
	/// the error.
	fn create() -> Result<(), NewPathBanlistError> {
		create_dir_all("./file_hasher_files").map_err(NewPathBanlistError::CreatingFileHasherDir)?;
		let mut file = File::create("./file_hasher_files/banlist").map_err(NewPathBanlistError::CreatingBanlist)?;

		let mut hasher = VarBlake2b::new(constants::HASH_OUTPUT_LENGTH).unwrap();
		let def_banned_list = ["./lost+found", "./.Trash-1000/", "./file_hasher_files/"];

		for string in def_banned_list.iter() {
			file.write(format!("{}\n", string).as_bytes()).map_err(NewPathBanlistError::WriteFileError)?;
			hasher.update(string.as_bytes());
		}

		file.write(format!("{}{}", constants::FIN_CHECKSUM_PREFIX, shared::blake2_to_checksum(hasher)).as_bytes())
		    .map_err(NewPathBanlistError::WriteFileError)?;
		Ok(())
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
		if let Some(checksum) = line.strip_prefix(constants::FIN_CHECKSUM_PREFIX) {
			return LineType::Checksum(checksum);
		}

		// If line is not identified as a comment or a checksum, it must be a bannedpath.
		LineType::BannedPath(line)
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

	/// Creates a PathBanlist without a backing file.
	pub(crate) fn new_dummy() -> PathBanlist {
		PathBanlist{banned_paths: HashMap::new()}
	}
}