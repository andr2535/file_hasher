use std::{error::Error, fmt};

#[derive(Debug)]
pub enum EDElementError {
	GetMetaDataError(String, std::io::Error),
	OpenFileError(String, std::io::Error),
	FileHashingError(String, FileHashingError),
	InvalidUtf8Link(String),
	VerifyLinkPathError(VerifyLinkPathError),
	VerifyError(EDElementVerifyError),
	LinkTargetInvalidUtf8(String),
}
impl Error for EDElementError {}
impl fmt::Display for EDElementError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		use EDElementError::*;
		match self {
			GetMetaDataError(path, err) => write!(f, "Error getting metadata of path \"{}\", error = {}", path, err),
			OpenFileError(path, err) => write!(f, "Error opening path \"{}\", error = {}", path, err),
			FileHashingError(path, err) => write!(f, "FileHashingError, {}, file = {}", err, path),
			InvalidUtf8Link(path) => write!(f, "link_path is not a valid utf-8 string!, path to link = {}", path),
			VerifyLinkPathError(err) => write!(f, "{}", err),
			VerifyError(err) => write!(f, "{}", err),
			LinkTargetInvalidUtf8(path) => write!(f, "link_target is not a valid utf-8 string!, path to link = {}", path),
		}
	}
}
impl From<VerifyLinkPathError> for EDElementError {
	fn from(err: VerifyLinkPathError) -> EDElementError {
		EDElementError::VerifyLinkPathError(err)
	}
}
impl From<EDElementVerifyError> for EDElementError {
	fn from(err: EDElementVerifyError) -> EDElementError {
		EDElementError::VerifyError(err)
	}
}

#[derive(Debug)]
pub struct FileHashingError {
	error: std::io::Error,
}
impl Error for FileHashingError {}
impl fmt::Display for FileHashingError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Error reading file = {}", self.error)
	}
}
impl From<std::io::Error> for FileHashingError {
	fn from(error: std::io::Error) -> FileHashingError {
		FileHashingError { error }
	}
}

#[derive(Debug)]
pub enum VerifyLinkPathError {
	LinkFileNoParentError(String, String),
	UnableToOpenLinkTarget(String, String, std::io::Error),
}
impl Error for VerifyLinkPathError {}
impl fmt::Display for VerifyLinkPathError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		use VerifyLinkPathError::*;
		match self {
			LinkFileNoParentError(path, link_target) => {
				write!(f, "Link with path '{}', has link_target: '{}', which doesn't have a parent!", path, link_target)
			},
			UnableToOpenLinkTarget(path, link_target, err) => {
				write!(f, "Error opening file linked to by: '{}', link_target: '{}', error: '{}'", path, link_target, err)
			},
		}
	}
}

#[derive(Debug)]
pub enum EDElementVerifyError {
	TimeChangedButFileCorrectError(String),
	TimeChangedAndFileChanged(String),
	InvalidChecksum(String),
	LinkTargetValidTimeChanged(String),
	LinkTargetInvalid(String),
	LinkTargetInvalidTimeChanged(String),
	PathIsDirectory(String),
	TimeChanged(String),
}
impl Error for EDElementVerifyError {}
impl fmt::Display for EDElementVerifyError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		use EDElementVerifyError::*;
		match self {
			TimeChangedButFileCorrectError(path) => write!(f, "File \"{}\" has a valid checksum, but the time has been changed", path),
			TimeChangedAndFileChanged(path) => write!(f, "File \"{}\" has an invalid checksum, and it's time has been changed", path),
			InvalidChecksum(path) => write!(f, "File \"{}\" has an invalid checksum", path),
			LinkTargetValidTimeChanged(path) => write!(f, "Modified time changed on symbolic link \"{}\"", path),
			LinkTargetInvalid(path) => write!(f, "Link \"{}\", has an invalid target path", path),
			LinkTargetInvalidTimeChanged(path) => {
				write!(f, "Link \"{}\", has an invalid target path, and it's modified time has changed", path)
			},
			PathIsDirectory(path) => write!(f, "Path \"{}\" is a directory", path),
			TimeChanged(path) => write!(f, "File with path \"{}\", has a different modified time than expected", path),
		}
	}
}

#[derive(Debug)]
pub enum EDElementParseError {
	NoStartBracket,
	EscapedCharacterMissing,
	NoFilePathTerminator,
	NoModifiedTimeTerminator,
	ModifiedTimeCouldNotBeParsed(std::num::ParseIntError),
	NoVariantInformation,
	IncompleteFileHash,
	FileHashDecodeError(hex::FromHexError),
	NoVariantTerminator,
	InvalidVariantIdentifier,
	NoTerminatorBracket,
}
impl Error for EDElementParseError {}
impl fmt::Display for EDElementParseError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		use EDElementParseError::*;
		match self {
			NoStartBracket => write!(f, "Missing start bracket"),
			EscapedCharacterMissing => write!(f, "Missing character after escaping character '\\'"),
			NoFilePathTerminator => write!(f, "Missing terminating character after path name"),
			NoModifiedTimeTerminator => write!(f, "Modified time string has no terminator character"),
			ModifiedTimeCouldNotBeParsed(err) => write!(f, "Modified time couldn't be parsed, err = {}", err),
			NoVariantInformation => write!(f, "EDElement is missing information about its variant type"),
			IncompleteFileHash => write!(f, "File_hash is incomplete"),
			FileHashDecodeError(err) => write!(f, "Error decoding file hash: {}", err),
			NoVariantTerminator => write!(f, "Missing terminating ')' character after file_hash, or link_target"),
			InvalidVariantIdentifier => write!(f, "Invalid variant identifier in EDElement string"),
			NoTerminatorBracket => write!(f, "Missing EDElement terminator bracket"),
		}
	}
}
impl From<std::num::ParseIntError> for EDElementParseError {
	fn from(err: std::num::ParseIntError) -> EDElementParseError {
		EDElementParseError::ModifiedTimeCouldNotBeParsed(err)
	}
}
impl From<hex::FromHexError> for EDElementParseError {
	fn from(err: hex::FromHexError) -> EDElementParseError {
		EDElementParseError::FileHashDecodeError(err)
	}
}
