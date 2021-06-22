use super::*;

#[derive(Debug)]
pub enum OpenPathBanlistError {
	UserDeniedNewList,
    NewPathBanlistError(NewPathBanlistError),
	DuplicateChecksum,
	IOError(std::io::Error),
	InvalidChecksum(String),
	MissingChecksum(String)
}
impl std::error::Error for OpenPathBanlistError { }
impl std::fmt::Display for OpenPathBanlistError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use OpenPathBanlistError::*;
		match self {
			UserDeniedNewList => write!(f, "banlist file could not be opened"),
			NewPathBanlistError(err) => write!(f, "Error opening pathbanlist: {}", err),
			DuplicateChecksum => write!(f, "More than one checksum in banlist, remove the redundant ones!"),
			IOError(err) => write!(f, "Error opening PathBanlist, IOError: {}", err),
			InvalidChecksum(hash_string) => write!(f, "Checksum for banlist is invalid.\n\
			If the current banlist is correct,\nReplace the checksum in the banlist file with the following:\n\
			{}{}", constants::FIN_CHECKSUM_PREFIX, hash_string),
			MissingChecksum(hash_string) => write!(f, "There is no checksum in the banlist file.\n\
			If the current banlist is correct,\nType the following line into the banlist file:\n\
			{}{}", constants::FIN_CHECKSUM_PREFIX, hash_string)
		}
	}
}
impl From<std::io::Error> for OpenPathBanlistError {
	fn from(err: std::io::Error) -> OpenPathBanlistError {
		OpenPathBanlistError::IOError(err)
	}
}
impl From<NewPathBanlistError> for OpenPathBanlistError {
	fn from(err: NewPathBanlistError) -> OpenPathBanlistError {
		OpenPathBanlistError::NewPathBanlistError(err)
	}
}

#[derive(Debug)]
pub enum NewPathBanlistError {
	UserDeniedNewList,
	CreatingFileHasherDir(std::io::Error),
	CreatingBanlist(std::io::Error),
	WriteFileError(std::io::Error)
}
impl std::error::Error for NewPathBanlistError { }
impl std::fmt::Display for NewPathBanlistError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		use NewPathBanlistError::*;
		match self {
			UserDeniedNewList => write!(f, "New banlist file could not be created due to user choice"),
			CreatingFileHasherDir(err) => write!(f, "Error creating file_hasher directory, Error = {}", err),
			CreatingBanlist(err) => write!(f, "Error creating file, Error = {}", err),
			WriteFileError(err) => write!(f, "Error writing to file, Error = {}", err)
		}
	}
}