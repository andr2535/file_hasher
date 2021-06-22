use super::*;
use crate::path_banlist::errors::*;

#[derive(Debug)]
pub enum EDListOpenError {
	CouldNotOpenFileHashesFile,
	IoError(std::io::Error),
	ChecksumsMissingError,
	UnsupportedEDListVersion(UnsupportedEDListVersion),
	InvalidXorChecksum,
	UndecodableXorChecksum(hex::FromHexError),
	InvalidFinChecksum,
	EDElementParseError(e_d_element::errors::EDElementParseError, usize),
	XorChecksumMismatch,
	FinChecksumMismatch,
	WriteBackupError(WriteBackupError)

}
impl std::error::Error for EDListOpenError { }
impl std::fmt::Display for EDListOpenError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use EDListOpenError::*;
		match self {
			CouldNotOpenFileHashesFile => write!(f, "file_hashes file could not be opened, or created"),
			IoError(err) => write!(f, "There was a problem reading from file, err = {}", err),
			ChecksumsMissingError => write!(f, "Missing first three lines with metadata about file_hashes"),
			UnsupportedEDListVersion(err) => write!(f, "{}", err),
			InvalidXorChecksum => write!(f, "Invalid xor_checksum_string at line 2 of file_hashes"),
			UndecodableXorChecksum(err) => write!(f, "error decoding xor_checksum to u8 array, err = {}", err),
			InvalidFinChecksum => write!(f, "Invalid fin_checksum_string at line 3 of file_hashes"),
			EDElementParseError(err, i) => write!(f, "Error interpreting EDElement from file_hashes, linecount = {}, err = {}", i + 4, err),
			XorChecksumMismatch => write!(f, "Mismatch between xor checksum in file and generated xor checksum"),
			FinChecksumMismatch => write!(f, "Mismatch between final checksum in file and generated final checksum"),
			WriteBackupError(err) => write!(f, "Error writing backup, err = {}", err)
		}
	}
}
impl From<std::io::Error> for EDListOpenError {
	fn from(err: std::io::Error) -> EDListOpenError {
		EDListOpenError::IoError(err)
	}
}
impl From<UnsupportedEDListVersion> for EDListOpenError {
	fn from(err: UnsupportedEDListVersion) -> EDListOpenError {
		EDListOpenError::UnsupportedEDListVersion(err)
	}
}
impl From<hex::FromHexError> for EDListOpenError {
	fn from(err: hex::FromHexError) -> EDListOpenError {
		EDListOpenError::UndecodableXorChecksum(err)
	}
}
impl From<(e_d_element::errors::EDElementParseError, usize)> for EDListOpenError {
	fn from(err: (e_d_element::errors::EDElementParseError, usize)) -> EDListOpenError {
		EDListOpenError::EDElementParseError(err.0, err.1)
	}
}
impl From<WriteBackupError> for EDListOpenError {
	fn from(err: WriteBackupError) -> EDListOpenError {
		EDListOpenError::WriteBackupError(err)
	}
}

#[derive(Debug)]
pub enum UnsupportedEDListVersion {
	Invalid(String),
	V1_0,
	MissingIdentifier
}
impl std::error::Error for UnsupportedEDListVersion { }
impl std::fmt::Display for UnsupportedEDListVersion {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use UnsupportedEDListVersion::*;
		match self {
			Invalid(identifier) => write!(f, "Invalid version identifier \"{}\" in file_hashes,\
			                                  \nmaybe the file is made by a future version of the program?", 
			                                  identifier),
			V1_0 => write!(f, "file_hashes version is 1.0, if you want to update the list,\
			                   \nyou should use file_hasher V1.0.1"),
			MissingIdentifier => write!(f, "The list_version identifier is missing from file_hashes.\
			                                \nThis might mean this file_hashes list is from before V1.0.0.\
			                                \nIf you want to update the list,\
			                                use V1.0.0 of this program to update the list to V1.0.")
		}
	}
}

#[derive(Debug)]
pub enum VerifyError {
	PathInBanlist(String),
	EDElementError(e_d_element::errors::EDElementError)
}
impl std::error::Error for VerifyError { }
impl std::fmt::Display for VerifyError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use VerifyError::*;
		match self {
			PathInBanlist(path) => write!(f, "\"{}\" is in the banlist.", path),
			EDElementError(err) => write!(f, "{}", err)
		}
	}
}
impl From<e_d_element::errors::EDElementError> for VerifyError {
	fn from(err: e_d_element::errors::EDElementError) -> VerifyError {
		VerifyError::EDElementError(err)
	}
}

#[derive(Debug)]
pub enum CreateError {
	IndexError(IndexError),
	EDElementError(e_d_element::errors::EDElementError)
}
impl std::error::Error for CreateError { }
impl std::fmt::Display for CreateError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use CreateError::*;
		match self {
			IndexError(err) => write!(f, "Error indexing files, Err = {}", err),
			EDElementError(err) => write!(f, "{}", err)
		}
	}
}
impl From<IndexError> for CreateError {
	fn from(err: IndexError) -> CreateError {
		CreateError::IndexError(err)
	}
}
impl From<e_d_element::errors::EDElementError> for CreateError {
	fn from(err: e_d_element::errors::EDElementError) -> CreateError {
		CreateError::EDElementError(err)
	}
}


#[derive(Debug)]
pub enum IndexError {
	CantGetSubDirError(String, String),
	IoError(std::io::Error),
	OsStringConvertError(String)
}
impl std::error::Error for IndexError { }
impl std::fmt::Display for IndexError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use IndexError::*;
		match self {
			CantGetSubDirError(path, err) => write!(f, "Error getting subdirs from dir {}, error = {}", path, err),
			IoError(err) => write!(f, "IoError during indexing, err = {}", err),
			OsStringConvertError(path) => write!(f, "Failed to convert OsString to String in path: {}", path)

		}
	}
}
impl From<std::io::Error> for IndexError {
	fn from(err: std::io::Error) -> IndexError {
		IndexError::IoError(err)
	}
}


#[derive(Debug)]
pub enum WriteBackupError {
	CreateDirectoryError(String),
	CreateFileError(String),
	WriteEDListToFileError(WriteEDListToFileError)
}
impl std::error::Error for WriteBackupError { }
impl std::fmt::Display for WriteBackupError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use WriteBackupError::*;
		match self {
			CreateDirectoryError(err) => write!(f, "Error creating hash_file_backups directory, Error = {}", err),
			CreateFileError(err) => write!(f, "Error creating backup file, err = {}", err),
			WriteEDListToFileError(err) => write!(f, "{}", err)
		}
	}
}
impl From<WriteEDListToFileError> for WriteBackupError {
	fn from(err: WriteEDListToFileError) -> WriteBackupError {
		WriteBackupError::WriteEDListToFileError(err)
	}
}
#[derive(Debug)]
pub enum WriteEDListToFileError {
	WriteError(String, String),
	FlushError(String, String)
}
impl std::error::Error for WriteEDListToFileError { }
impl std::fmt::Display for WriteEDListToFileError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use WriteEDListToFileError::*;
		match self {
			WriteError(file_name, err) => write!(f, "Error writing to the file {}. err = {}", file_name, err),
			FlushError(file_name, err) => write!(f, "Error flushing the file {}. err = {}", file_name, err),
		}
	}
}
#[derive(Debug)]
pub enum WriteHashFileError {
	WriteEDListToFileError(WriteEDListToFileError),
	ErrorCreatingFile(String)
}
impl std::error::Error for WriteHashFileError { }
impl std::fmt::Display for WriteHashFileError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use WriteHashFileError::*;
		match self {
			WriteEDListToFileError(err) => write!(f, "{}", err),
			ErrorCreatingFile(err) => write!(f, "Error creating file, Error = {}", err),
		}
	}
}
impl From<WriteEDListToFileError> for WriteHashFileError {
	fn from(err: WriteEDListToFileError) -> WriteHashFileError {
		WriteHashFileError::WriteEDListToFileError(err)
	}
}

#[derive(Debug)]
pub enum SyncFromError {
	OpenPathBanlistError(OpenPathBanlistError),
	EDListOpenError(EDListOpenError),
	GetPathParentError,
	IoError(std::io::Error),
	InvalidUtf8Link(String),
	ChecksumValidationError
}
impl std::error::Error for SyncFromError { }
impl std::fmt::Display for SyncFromError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use SyncFromError::*;
		match self {
			OpenPathBanlistError(err) => write!(f, "Error: {}, prevented PathBanlist from opening", err),
			EDListOpenError(err) => write!(f, "Error: {}, prevented EDList from opening", err),
			GetPathParentError => write!(f, "Error getting parent of path during move or copy operation"),
			IoError(err) => write!(f, "IOError During sync FileOperation: {}", err),
			InvalidUtf8Link(err) => write!(f, "Invalid UTF-8 symbolic link: {}", err),
			ChecksumValidationError => write!(f, "There was an error validation the sync operations\nPlease restore the latest EDList backup.")
		}
	}
}
impl From<OpenPathBanlistError> for SyncFromError {
	fn from(err: OpenPathBanlistError) -> SyncFromError {
		SyncFromError::OpenPathBanlistError(err)
	}
}
impl From<EDListOpenError> for SyncFromError {
	fn from(err: EDListOpenError) -> SyncFromError {
		SyncFromError::EDListOpenError(err)
	}
}
impl From<std::io::Error> for SyncFromError {
	fn from(err: std::io::Error) -> SyncFromError {
		SyncFromError::IoError(err)
	}
}