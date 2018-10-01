extern crate blake2;
use std::{fs, fs::File, io::prelude::Read, time::SystemTime};
use self::blake2::{Blake2b, digest::{Input, VariableOutput}};

#[derive(Debug)]
/// FileElement is a struct that contains the fields that
/// a file needs, but a symbolic link does not need.
struct FileElement {
	file_hash: [u8; 32]
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
/// variant_fields can store either information about a
/// file, or it can store information about a link.
/// 
/// element_hash contains a hash value of all the fields in
/// the EDElement object.
pub struct EDElement {
	path: String,
	modified_date: u64,
	variant_fields: EDVariantFields,
	element_hash: [u8; 32]
}
impl EDElement {
	fn from_internal(path:String, modified_date: u64, variant_fields: EDVariantFields) -> EDElement {
		let mut hasher = Blake2b::new(32).unwrap();
		hasher.process(path.as_bytes());
		hasher.process(format!("{}", modified_date).as_bytes());
		match &variant_fields {
			EDVariantFields::File(file) => hasher.process(&file.file_hash),
			EDVariantFields::Link(link) => hasher.process(link.link_path.as_bytes())
		}
		let mut element_hash = [0u8; 32];
		hasher.variable_result(&mut element_hash).unwrap();

		return EDElement{path: path, modified_date: modified_date, variant_fields:variant_fields, element_hash: element_hash};
	}
	/// from_path generates an EDElement from a path.
	/// It detects automatically whether the path
	/// refers to a link or a file.
	pub fn from_path(path:String) -> Result<EDElement, String> {
		match File::open(&path) {
			Ok(file) => {
				match fs::symlink_metadata(&path) {
					Ok(metadata) => {
						if metadata.is_dir() {return Result::Err(String::from("The path is a directory!"));}
						let modified_date = metadata.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

						if metadata.is_file() {
							// The path is a file.
							let hash = EDElement::hash_file(file);
							let file_fields = EDVariantFields::File(FileElement{file_hash: hash});
							return Result::Ok(EDElement::from_internal(path, modified_date, file_fields));
						}
						else {
							// The path is a symbolic link
							let link_path = match fs::read_link(&path).unwrap().to_str(){
								Some(link_path) => String::from(link_path),
								None => panic!("link_path is not a valid utf-8 string!")
							};
							let link_fields = EDVariantFields::Link(LinkElement{link_path: link_path});
							return Result::Ok(EDElement::from_internal(path, modified_date, link_fields));
						}
					},
					Err(err) => panic!(format!("Error getting file metadata {}", err))
				};
			},
			Err(err) => return Result::Err(format!("Error opening file {}", err))
		}
	}
	/// hash_file reads a file, and creates a hash for it in an
	/// u8 vector, of length 32.
	/// If there is trouble reading the file, hash_file will panic.
	/// (Probably should be changed in the future)
	fn hash_file(mut file:File) -> [u8; 32] {
		let buffer_size = 20 * 1024 * 1024; // Buffer_size = 20MB
		let mut buffer = vec![0u8; buffer_size];
		let mut hasher = Blake2b::new(32).unwrap();
		loop {
			let result_size = file.read(&mut buffer).unwrap();
			
			if result_size == buffer_size{
				hasher.process(&buffer);
			}
			else{
				hasher.process(&buffer[0..result_size]);
				break;
			}
		}
		let mut output = [0u8; 32];
		hasher.variable_result(&mut output).unwrap();
		return output;
	}
}
