extern crate blake2;

use std::{fs::{File, create_dir_all}, io::{BufRead, BufReader, Write}, collections::HashMap};
use self::blake2::{Blake2b, digest::{Input, VariableOutput}};
use interfacers::UserInterface;

const CHECKSUM_PREFIX:&str = "CHECKSUM = ";
const HASH_OUTPUT_LENGTH:usize = 32;

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

#[derive(Debug)]
/// PathBanlist is a HashSet that contains all the paths that
/// should not be hashed by the EDList objects.
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
					else if create_new == "NO" {return Result::Err(String::from("banlist file could not be opened"));}
				}
			}
		};
		let buf_reader = BufReader::new(file);
		
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		let mut checksum: Option<String> = Option::None;
		let mut banned_paths: HashMap<char, CharMapper> = HashMap::new();

		for line in buf_reader.lines() {
			let line = match line {
				Ok(line) => line,
				Err(err) => return Result::Err(String::from(format!("Error reading line, error message = {}", err)))
			};
			
			match PathBanlist::identify_line(&line) {
				LineType::BannedPath => {
					hasher.process(line.as_bytes());

					PathBanlist::insert_to_banlist(&mut banned_paths, &line);
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
	/// Attempts to create a new banlist file, and then opens it using
	/// the open function.
	/// Requires a object that implements UserInterface, so that it can send it
	/// on to the open function.
	/// When it fails, it returns a string containing information about
	/// the error.
	fn new(banlist_interfacer: impl UserInterface) -> Result<PathBanlist, String> {
		match create_dir_all("./file_hasher_files") {
			Ok(_res) => (),
			Err(err) => return Err(format!("Error creating file_hasher directory, Error = {}", err))
		};
		
		let mut file = match File::create("./file_hasher_files/banlist") {
			Ok(file) => file,
			Err(err) => return Err(format!("Error creating file, Error = {}", err))
		};
		
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		let def_banned_list = ["./lost+found/", "./.Trash-1000/", "./file_hasher_files/"];

		for string in def_banned_list.iter() {
			match file.write(format!("{}\n", string).as_bytes()) {
				Ok(_len) => (),
				Err(err) => return Err(format!("Error writing line to file, Error = {}", err))
			}
			hasher.process(string.as_bytes());
		}

		let write_result = file.write(format!("{}{}", CHECKSUM_PREFIX, PathBanlist::blake2_to_string(hasher)).as_bytes());

		match write_result {
			Ok(_len) => return PathBanlist::open(banlist_interfacer),
			Err(err) => return Err(format!("Error writing checksum to banlist, Error = {}", err))
		};
	}

	/// Converts a Blake2b object into a string.
	/// The hash is output in capital hexadecimal letters.
	pub fn blake2_to_string(hasher:Blake2b) -> String {
		let mut hash = [0u8; HASH_OUTPUT_LENGTH];
		hasher.variable_result(&mut hash).unwrap();

		let mut hash_string = String::with_capacity(HASH_OUTPUT_LENGTH*2);
		for byte in hash.iter() {
			hash_string.push_str(&format!("{:02X}", byte));
		}

		return hash_string;
	}

	/// identify_line determines if a line is a comment, a checksum or a banned path.
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

		// Figure out whether line is a checksum.
		let mut line_checksum = String::with_capacity(checksum_prefix.len());
		for (checksum_char, line_char) in checksum_prefix.chars().zip(line.chars()) {
			if checksum_char == line_char {
				line_checksum.push(line_char);
			}
			else {
				break;
			}
		}
		// If line_checksum length has reached checksum_prefix length, we know that
		// line_checksum has the CHECKSUM_PREFIX as prefix.
		if checksum_prefix.len() == line_checksum.len() {
			return LineType::Checksum(String::from(&line[checksum_prefix.len()..line.len()]));
		}

		// If line is not identified as a comment or a checksum, it must be a bannedpath.
		LineType::BannedPath
	}
	
	/// Used internally by the path_banlist open constructor,
	/// to insert the needed paths into the banlist.
	fn insert_to_banlist(banlist:&mut HashMap<char, CharMapper>, line:&String) {
		// Unsafe variables.
		let mut last_hashmap:Option<*mut HashMap<char, CharMapper>> = None;
		let mut hashmap = banlist as *mut HashMap<char, CharMapper>;

		let mut last_char:Option<char> = Option::None;
		
		for character in line.chars() {
			last_char = Some(character);

			// Used to know if there was not anything mapped to the character.
			let mut none_in_hashmap = false;
			match unsafe {(*hashmap).get_mut(&character) } {
				Some(char_map) => {
					match char_map {
						CharMapper::More(ref mut next) => {
							last_hashmap = Some(hashmap);
							hashmap = next as *mut HashMap<char, CharMapper>;
						},
						// We return, since we hit a terminator before the line reaches its end.
						CharMapper::Terminator => return
					}
				}
				None => {
					none_in_hashmap = true;
				}
			}
			if none_in_hashmap {
				unsafe {(*hashmap).insert(character, CharMapper::More(HashMap::new()));}

				match unsafe {(*hashmap).get_mut(&character)} {
					Some(char_map) => {
						match char_map {
							CharMapper::More(ref mut next) => {
								last_hashmap = Some(hashmap);
								hashmap = next as *mut HashMap<char, CharMapper>;
							},
							CharMapper::Terminator => panic!("Terminator set in path_banlist, where there can't be any!")
						}
					}
					// There will always be a some, since we just inserted the value.
					None => panic!("Value that should have been inserted doesn't exist in path_banlist!")
				}
			}
		}
		// Add terminator instead of the last hashmap.
		match last_hashmap {
			Some(hashmap) => {
				match last_char {
					Some(character) => {
						unsafe {(*hashmap).insert(character, CharMapper::Terminator);}
					}
					None => ()
				}
			},
			None => ()
		}
	}
	/// Used to test whether the given path has any
	/// of its prefixes defined in the banlist.
	/// Returns true, if there is such a prefix, else it
	/// returns false.
	pub fn is_in_banlist(&self, path: &String) -> bool {
		let mut hashmap = &self.banned_paths;
		for character in path.chars() {
			match hashmap.get(&character) {
				Some(char_map) => {
					match char_map {
						CharMapper::More(next_map) => hashmap = next_map,
						CharMapper::Terminator => return true
					}
				},
				None => {
					return false;
				}
			}
		}
		return false;
	}
}