extern crate blake2;
use std::{fs, fs::File, io::prelude::Read, time::SystemTime};
use self::blake2::{Blake2b, digest::{Input, VariableOutput}};

#[derive(Debug)]
/// file_element is a struct for an element that is a file.
/// It needs to know the hashed value of the files content.
struct FileElement {
	file_hash: [u8; 32]
}

#[derive(Debug)]
/// link_element is a struct for an element that is a
/// symbolic link, it only needs a target, which we call
/// link_path here.
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
/// element_type_fields can store either information about a
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
	pub fn from_file(path:String) -> Result<EDElement, String> {
		match File::open(&path) {
			Ok(file) => {
				let hash = EDElement::hash_file(file);
				let modified_date = match fs::symlink_metadata(&path) {
					Ok(metadata) => metadata.modified().unwrap().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
					Err(_err) => panic!("OS or filesystem doesn't support modified time!")
				};
				let file_fields = EDVariantFields::File(FileElement{file_hash: hash});
				return Result::Ok(EDElement::from_internal(path, modified_date, file_fields));
			},
			Err(_err) => () // Returning error below
		}
		return Result::Err(String::from("Error creating EDElement from file"));
	}
	/// hash_file reads a file, and creates a hash for it in a u8 vector.
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
				let mut tmp_buffer = Vec::new();
				for i in 0..result_size { // Test if this is valid...
					tmp_buffer.push(buffer[i]);
				}
				hasher.process(&tmp_buffer);
				break;
			}
		}
		let mut output = [0u8; 32];
		hasher.variable_result(&mut output).unwrap();
		return output;
	}
}
