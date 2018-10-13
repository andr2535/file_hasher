extern crate blake2;
use std::{fs, fs::File, io::prelude::Read, time::SystemTime};
use self::blake2::{Blake2b, digest::{Input, VariableOutput}};

const HASH_OUTPUT_LENGTH: usize = 32;

#[derive(Debug)]
/// FileElement is a struct that contains the fields that
/// a file needs, but a symbolic link does not need.
struct FileElement {
	file_hash: [u8; HASH_OUTPUT_LENGTH]
}

#[derive(Debug)]
/// LinkElement is a struct that contains the fields, that
/// a symbolic link needs, that a file does not need.
struct LinkElement {
	link_path: String
}

#[derive(Debug)]
/// EDVariantFields is used to manage whether we are storing
/// a file or a symbolic link.
enum EDVariantFields {
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
			EDVariantFields::Link(link) => hasher.process(link.link_path.as_bytes())
		}
		let mut element_hash = [0u8; HASH_OUTPUT_LENGTH];
		hasher.variable_result(&mut element_hash).unwrap();

		EDElement{path: path, modified_time: modified_time, variant_fields:variant_fields, element_hash: element_hash}
	}
	/// from_path generates an EDElement from a path.
	/// It detects automatically whether the path
	/// refers to a link or a file.
	pub fn from_path(path:String) -> Result<EDElement, String> {
		let file = match File::open(&path) {
			Ok(file) => file,
			Err(err) => return Result::Err(format!("Error opening file {}", err))
		};

		let metadata = match fs::symlink_metadata(&path) {
			Ok(metadata) => metadata,
			Err(err) => panic!(format!("Error getting file metadata {}", err))
		};

		if metadata.is_dir() {return Result::Err(String::from("The path is a directory!"));}
		let modified_time = metadata.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

		if metadata.is_file() {
			// The path is a file.
			let hash = EDElement::hash_file(file);
			let file_fields = EDVariantFields::File(FileElement{file_hash: hash});
			return Result::Ok(EDElement::from_internal(path, modified_time, file_fields));
		}
		else {
			// The path is a symbolic link
			let link_path = match fs::read_link(&path).unwrap().to_str(){
				Some(link_path) => String::from(link_path),
				None => panic!("link_path is not a valid utf-8 string!")
			};
			let link_fields = EDVariantFields::Link(LinkElement{link_path: link_path});
			return Result::Ok(EDElement::from_internal(path, modified_time, link_fields));
		}
	}

	/// test_integrity tests the integrity of the EDElement against
	/// the file or symbolic link it points to.
	/// If the symbolic_link or file has changed, or there has
	/// been corruption in the EDElement struct, a string
	/// containing the error will be given back.
	/// If not, it returns None.
	pub fn test_integrity(&self) -> Option<String> {

		Option::Some(String::from("Not implemented yet"))
	}
	/// hash_file reads a file, and creates a hash for it in an
	/// u8 vector, of length HASH_OUTPUT_LENGTH.
	/// If there is trouble reading the file, hash_file will panic.
	/// (Probably should be changed in the future)
	fn hash_file(mut file:File) -> [u8; HASH_OUTPUT_LENGTH] {
		let buffer_size = 40 * 1024 * 1024; // Buffer_size = 40MB
		let mut buffer = vec![0u8; buffer_size];
		let mut hasher = Blake2b::new(HASH_OUTPUT_LENGTH).unwrap();
		loop {
			let result_size = file.read(&mut buffer).unwrap();
			hasher.process(&buffer[0..result_size]);
			if result_size != buffer_size {break;}
		}
		let mut output = [0u8; HASH_OUTPUT_LENGTH];
		hasher.variable_result(&mut output).unwrap();
		output
	}

	/// Returns a hash of the entire EDElement.
	/// This hash does not represent the file_hash, it
	/// represents the entire element.
	/// So if anything changes inside the EDElement,
	/// this hash would be invalid.
	pub fn get_hash(&self) -> &[u8; HASH_OUTPUT_LENGTH] {
		return &self.element_hash;
	}

	/// Returns an immutable reference to the path
	/// of this element.
	pub fn get_path(&self) -> &String {
		return &self.path;
	}

	/// Convert EDElement to a String representation, this
	/// string can be parsed back to an EDElement
	/// by the function from_str.
	pub fn to_string(&self) -> String {
		let variant_fields = match &self.variant_fields {
			EDVariantFields::File(file) => {
				let mut file_hash = String::new();
				for element in file.file_hash.into_iter(){
					file_hash += &format!("{:02X}", element);
				}
				format!("file({})", file_hash)
			},
			EDVariantFields::Link(link) => format!("link({})", link.link_path.replace("\\", "\\\\").replace(")", "\\)"))
		};
		format!("[{},{},{}]", self.path.replace("\\", "\\\\").replace(",", "\\,"), self.modified_time, variant_fields)
	}

	/// Parses a string into an EDElement struct, if the string
	/// does not describe a valid EDElement struct, it will return
	/// a String containing an error message.
	pub fn from_str(element_string: &String) -> Result<EDElement, String> {
		enum Phase {
			BeforeFirstBracket,
			ReadingPath,
			ReadingTime,
			VariantDetect,
			ReadingLink,
			ReadingFileHash,
			BeforeLastBracket
		}
		let mut cur_phase = Phase::BeforeFirstBracket;

		let mut path = String::new();
		let mut time_string = String::new();
		let mut variant_string = String::new();
		let mut file_hash:Vec<u8> = vec![];
		let mut link_path = String::new();

		let mut last_file_hash_char:Option<char> = Option::None;
		let mut escape_char_set = false;

		let mut finished_parsing = false;

		for character in element_string.chars() {
			match cur_phase {
				Phase::BeforeFirstBracket => {
					if character != '[' {return Result::Err(String::from("Missing start bracket"));}
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
							if variant_string == "file" {
								cur_phase = Phase::ReadingFileHash;
							}
							else if variant_string == "link" {
								cur_phase = Phase::ReadingLink;
							}
							else {return Result::Err(String::from("Invalid variant_string"));}
						},
						_ => variant_string.push(character)
					}
				},
				Phase::ReadingFileHash => {
					match last_file_hash_char {
						Some(last_char) => {
							if character == ')' {
								return Result::Err(String::from("Invalid hash length"));
							}
							else {
								match u8::from_str_radix(&format!("{}{}", last_char, character), 16) {
									Ok(number) => file_hash.push(number),
									Err(_err) => return Result::Err(String::from("Parse error reading hexadecimal file_hash"))
								}
								last_file_hash_char = Option::None;
							}
						},
						None => {
							if character == ')'{
								cur_phase = Phase::BeforeLastBracket;
							}
							else {
								last_file_hash_char = Option::Some(character);
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
					if character != ']' {return Result::Err(String::from("Last bracket missing from EDElement string!"));}
					else {finished_parsing = true; break;} // Finished generating variables.
				}
			};
		}

		if !finished_parsing {
			return Result::Err(String::from("String parsing did not finish"));
		}

		// Finished fetching data from string, converting to proper types, and
		// Returning result.
		let modified_time = match u64::from_str_radix(&time_string, 10) {
			Ok(value) => value,
			Err(_err) => return Result::Err(String::from("Error parsing modified time"))
		};

		if variant_string == "file" {
			// Create Result with EDElement, that has a FileElement.
			if file_hash.len() != HASH_OUTPUT_LENGTH {return Result::Err(String::from("File hash has an invalid length"))};
			let mut file_hash_array = [0u8; HASH_OUTPUT_LENGTH];
			for (place, element) in file_hash_array.iter_mut().zip(file_hash.iter()) {
				*place = *element;
			}
			let variant_fields = EDVariantFields::File(FileElement{file_hash: file_hash_array});
			return Result::Ok(EDElement::from_internal(path, modified_time, variant_fields));
		}

		else {
			// If variant_string is not file, it must be "link".
			// Create Result with EDElement, that has a LinkElement.
			let variant_fields = EDVariantFields::Link(LinkElement{link_path: link_path});
			return Result::Ok(EDElement::from_internal(path, modified_time, variant_fields));
		}
	}
}