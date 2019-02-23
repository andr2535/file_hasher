use std::{fs, fs::File, io::prelude::Read, time::SystemTime};
use blake2::{Blake2b, digest::{Input, VariableOutput}};

use crate::core::constants::HASH_OUTPUT_LENGTH;

#[derive(Debug)]
/// FileElement is a struct that contains the fields that
/// a file needs, but a symbolic link does not need.
pub struct FileElement {
	pub file_hash: [u8; HASH_OUTPUT_LENGTH]
}

#[derive(Debug)]
/// LinkElement is a struct that contains the fields, that
/// a symbolic link needs, that a file does not need.
pub struct LinkElement {
	pub link_target: String
}

#[derive(Debug)]
/// EDVariantFields is used to manage whether we are storing
/// a file or a symbolic link.
pub enum EDVariantFields {
	File(FileElement),
	Link(LinkElement)
}

#[derive(Debug)]
/// EDElement, a shorthand for Error-detect-element
/// It should be used by a EDList object, for safely storing
/// metadata about files and links.
/// 
/// path is used for storing the path for the element
/// 
/// modified_time is used for storing the exact time of the
/// last modification of the file or link.
///
/// variant_fields can store either information about a
/// file, or it can store information about a link.
/// 
/// element_hash contains a hash value of all the fields in
/// the EDElement object.
pub struct EDElement {
	path: String,
	modified_time: u64,
	variant_fields: EDVariantFields,
	element_hash: [u8; HASH_OUTPUT_LENGTH]
}
impl EDElement {
	fn from_internal(path:String, modified_time: u64, variant_fields: EDVariantFields) -> EDElement {
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		hasher.process(path.as_bytes());
		hasher.process(modified_time.to_string().as_bytes());
		match &variant_fields {
			EDVariantFields::File(file) => hasher.process(&file.file_hash),
			EDVariantFields::Link(link) => hasher.process(link.link_target.as_bytes())
		}
		let mut element_hash = [0u8; HASH_OUTPUT_LENGTH];
		hasher.variable_result(&mut element_hash).unwrap();

		EDElement{path, modified_time, variant_fields, element_hash}
	}
	/// from_path generates an EDElement from a path.
	/// It detects automatically whether the path
	/// refers to a link or a file.
	/// 
	/// Returns an error if the path refers to a directory.
	/// Or if in some other way processing of the file does
	/// not complete correctly.
	/// 
	/// Panics if the path is a symbolic link and its
	/// link_path is not a valid utf-8 string.
	pub fn from_path(path:String) -> Result<EDElement, String> {
		let metadata = match fs::symlink_metadata(&path) {
			Ok(metadata) => metadata,
			Err(err) => return Err(format!("Error getting metadata of path \"{}\", error = {}", path, err))
		};

		if metadata.is_dir() {return Err("The path is a directory!".to_string());}
		let modified_time = metadata.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

		if metadata.is_file() {
			// The path is a file.
			let file = match File::open(&path) {
				Ok(file) => file,
				Err(err) => return Err(format!("Error opening path \"{}\", error = {}", path, err))
			};
			let hash = match EDElement::hash_file(file) {
				Ok(hash) => hash,
				Err(err) => return Err(format!("Error reading file {}, error = {}", path, err))
			};
			let file_fields = EDVariantFields::File(FileElement{file_hash: hash});
			Ok(EDElement::from_internal(path, modified_time, file_fields))
		}
		else {
			// The path is a symbolic link
			let link_path = match fs::read_link(&path).unwrap().to_str(){
				Some(link_path) => link_path.to_string(),
				None => panic!(format!("link_path is not a valid utf-8 string!, path to link = {}", path))
			};
			let link_fields = EDVariantFields::Link(LinkElement{link_target: link_path});
			Ok(EDElement::from_internal(path, modified_time, link_fields))
		}
	}
	/// Does a cursory test for if the path has been deleted,
	/// or if the modified time of the path has been changed.
	/// 
	/// If the metadata does not match the stored metadata, a
	/// Err<String> is returned.
	pub fn test_metadata(&self) -> Result<(), String> {
		let metadata = match fs::symlink_metadata(&self.path) {
			Ok(metadata) => metadata,
			Err(_err) => return Err(format!("Could not open path \"{}\"", &self.path))
		};
		if metadata.is_dir() {return Err(format!("Path \"{}\" is a directory", &self.path))}
		let modified_time = metadata.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
		if modified_time != self.modified_time {
			Err(format!("File with path \"{}\", has a different modified time than expected", &self.path))
		}
		else {Ok(())}
	}

	/// test_integrity tests the integrity of the EDElement against
	/// the file or symbolic link it points to.
	/// 
	/// If the symbolic_link or file has changed, or there has
	/// been corruption in the EDElement struct, an Err
	/// containing a string describing the error will be returned.
	/// If the integrity test went fine, it will return an Ok(()).
	pub fn test_integrity(&self) -> Result<(), String> {
		let metadata = match fs::symlink_metadata(&self.path) {
			Ok(metadata) => metadata,
			Err(err) => return Err(format!("Error reading metadata from file {}, err = {}", &self.path, err))
		};
		if metadata.is_dir() {return Err(format!("Path {} is a directory, directories cannot be a EDEelement!", &self.path));}
		
		let time_changed = {
			let modified_time = metadata.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
			modified_time != self.modified_time
		};
		
		match &self.variant_fields {
			EDVariantFields::File(file_element) => {
				let file = match File::open(&self.path) {
					Ok(file) => file,
					Err(err) => return Err(format!("Error opening file {} for testing, err = {}", &self.path, err))
				};
				let file_hash = match EDElement::hash_file(file) {
					Ok(file_hash) => file_hash,
					Err(err) => return Err(format!("Error trying to read file {}, err = {}", &self.path, err))
				};
				if file_hash == file_element.file_hash {
					if time_changed {
						Err(format!("File \"{}\" has a valid checksum, but the time has been changed", &self.path))
					}
					else {
						Ok(())
					}
				}
				else if time_changed {
					Err(format!("File \"{}\" has an invalid checksum, and it's time has been changed", &self.path))
				}
				else {
					Err(format!("File \"{}\" has an invalid checksum", &self.path))
				}
			},
			EDVariantFields::Link(link_element) => {
				let link_path = match fs::read_link(&self.path).unwrap().to_str() {
					Some(link_path) => link_path.to_string(),
					None => panic!("link_path is not a valid utf-8 string!")
				};
				if link_path == link_element.link_target {
					if time_changed {
						Err(format!("Time changed on link \"{}\", but link has valid target path", &self.path))
					}
					else {
						Ok(())
					}
				}
				else if time_changed {
					Err(format!("Link \"{}\", has an invalid target path, and it's modified time has changed", &self.path))
				}
				else {
					Err(format!("Link \"{}\", has an invalid target path", &self.path))
				}
			}
		}
	}
	/// hash_file reads a file, and creates a hash for it in an
	/// u8 vector, of length HASH_OUTPUT_LENGTH.
	/// If there is trouble reading the file, we will return
	/// the error given.
	fn hash_file(mut file:File) -> Result<[u8; HASH_OUTPUT_LENGTH], std::io::Error> {
		let buffer_size = 40 * 1024 * 1024; // Buffer_size = 40MB
		let mut buffer = vec![0u8; buffer_size];
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		loop {
			let result_size = match file.read(&mut buffer) {
				Ok(res) => res,
				Err(err) => return Err(err)
			};
			hasher.process(&buffer[0..result_size]);
			if result_size != buffer_size {break;}
		}
		let mut output = [0u8; HASH_OUTPUT_LENGTH];
		hasher.variable_result(&mut output).unwrap();
		Ok(output)
	}

	/// Returns a hash of the entire EDElement.
	/// This hash does not represent the file_hash, it
	/// represents the entire EDElement.
	/// So if anything changes inside the EDElement,
	/// this hash would be invalid.
	pub fn get_hash(&self) -> &[u8; HASH_OUTPUT_LENGTH] {
		&self.element_hash
	}

	/// Returns an immutable reference to the path
	/// of this EDElement.
	pub fn get_path(&self) -> &str {
		&self.path
	}

	/// Returns the path of this EDElement as an owned String.
	/// This will drop the EDElement in the process.
	pub fn take_path(mut self) -> String {
		std::mem::replace(&mut self.path, String::new())
	}

	pub fn get_variant(&self) -> &EDVariantFields {
		&self.variant_fields
	}

	/// Convert EDElement to a String representation, this
	/// string can be parsed back to an EDElement
	/// by the function from_str.
	pub fn to_string(&self) -> String {
		let variant_fields = match &self.variant_fields {
			EDVariantFields::File(file) => {
				let mut file_hash = String::with_capacity(HASH_OUTPUT_LENGTH*2);
				for element in file.file_hash.iter(){
					file_hash += &format!("{:02X}", element);
				}
				format!("file({})", file_hash)
			},
			EDVariantFields::Link(link) => format!("link({})", link.link_target.replace("\\", "\\\\").replace(")", "\\)"))
		};
		format!("[{},{},{}]", self.path.replace("\\", "\\\\").replace(",", "\\,"), self.modified_time, variant_fields)
	}

	/// Parses a string into an EDElement struct, if the string
	/// does not describe a valid EDElement struct, it will return
	/// a String containing an error message.
	pub fn from_str(element_string: &str) -> Result<EDElement, String> {
		#[derive(PartialEq)]
		enum Phase {
			BeforeFirstBracket,
			ReadingPath,
			ReadingTime,
			VariantDetect,
			ReadingLink,
			ReadingFileHash,
			BeforeLastBracket,
			Finished
		}
		let mut cur_phase = Phase::BeforeFirstBracket;

		let mut path = String::new();
		let mut time_string = String::new();
		let mut variant_string = String::new();
		let mut file_hash:Vec<u8> = vec![];
		let mut link_path = String::new();

		let mut last_file_hash_char:Option<char> = None;
		let mut escape_char_set = false;

		for character in element_string.chars() {
			match cur_phase {
				Phase::BeforeFirstBracket => {
					if character != '[' {return Err("Missing start bracket".to_string());}
					cur_phase = Phase::ReadingPath;
				},
				Phase::ReadingPath => {
					if escape_char_set {
						escape_char_set = false;
						path.push(character);
					}
					else {match character {
						'\\' => escape_char_set = true,
						','  => cur_phase = Phase::ReadingTime,
						 _   => path.push(character)
					}}
				},
				Phase::ReadingTime => {
					match character {
						',' => cur_phase = Phase::VariantDetect,
						 _  => time_string.push(character)
					}
				},
				Phase::VariantDetect => {
					match character {
						'(' => {
							match variant_string.as_ref() {
								"file" => cur_phase = Phase::ReadingFileHash,
								"link" => cur_phase = Phase::ReadingLink,
								_ => return Err("Invalid variant_string".to_string())
							}
						},
						_ => variant_string.push(character)
					}
				},
				Phase::ReadingFileHash => {
					match last_file_hash_char {
						Some(last_char) => {
							if character == ')' {return Err("Invalid hash length".to_string());}
							else {
								match u8::from_str_radix(&format!("{}{}", last_char, character), 16) {
									Ok(number) => file_hash.push(number),
									Err(_err) => return Err("Parse error reading hexadecimal file_hash".to_string())
								}
								last_file_hash_char = None;
							}
						},
						None => {
							if character == ')'{
								cur_phase = Phase::BeforeLastBracket;
							}
							else {
								last_file_hash_char = Some(character);
							}
						}
					}
				},
				Phase::ReadingLink => {
					if escape_char_set {
						escape_char_set = false;
						link_path.push(character);
					}
					else {match character {
						'\\' => escape_char_set = true,
						')'  => cur_phase = Phase::BeforeLastBracket,
						 _   => link_path.push(character)
					}}

				},
				Phase::BeforeLastBracket => {
					if character == ']' {cur_phase = Phase::Finished; break;} // Finished generating variables.
					else {return Err("Last bracket missing from EDElement string!".to_string());}
				},
				Phase::Finished => panic!("Match on cur_phase with Phase::Finished, should not be possible!")
			};
		}
		if cur_phase != Phase::Finished {
			return Err("String parsing did not finish".to_string());
		}

		// Finished fetching data from string, converting to proper types, and
		// Returning result.
		let modified_time = match u64::from_str_radix(&time_string, 10) {
			Ok(value) => value,
			Err(_err) => return Err("Error parsing modified time".to_string())
		};

		match variant_string.as_ref() {
			"file" => {
				// Create Result with EDElement, that has a FileElement.
				if file_hash.len() != HASH_OUTPUT_LENGTH {return Err("File hash has an invalid length".to_string())};
				let mut file_hash_array = [0u8; HASH_OUTPUT_LENGTH];
				for (place, element) in file_hash_array.iter_mut().zip(file_hash.iter()) {
					*place = *element;
				}
				let variant_fields = EDVariantFields::File(FileElement{file_hash: file_hash_array});
				Ok(EDElement::from_internal(path, modified_time, variant_fields))
			},
			"link" => {
				// If variant_string is not file, it must be "link".
				// Create Result with EDElement, that has a LinkElement.
				let variant_fields = EDVariantFields::Link(LinkElement{link_target: link_path});
				Ok(EDElement::from_internal(path, modified_time, variant_fields))
			},
			_ => Err("variant_string was invalid".to_string())
		}
	}
}
impl AsRef<EDElement> for EDElement {
	#[inline]
	fn as_ref(&self) -> &EDElement {
		self
	}
}