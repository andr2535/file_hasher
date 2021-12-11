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

pub trait InterfacerReturnType<T = Self>: TryFrom<String> {
	/// Returns the accepted answers from the user.
	/// If return value is None, then an exhaustive list of valid
	/// values cannot be generated.
	fn valid_answers() -> Option<&'static [&'static str]>;
}

pub trait UserInterface {
	/// Gives the message to the user, and returns
	/// the users answer to the caller without the
	/// endline character.
	fn get_user_answer<T: TryFrom<String> + InterfacerReturnType>(&self, message: &str) -> T
	where <T as TryFrom<String>>::Error: std::fmt::Display;

	/// Gives a message, that should be shown to the user,
	/// but the user can't reply to it.
	fn send_message(&self, message: &str);
}
pub struct StubUserInterface {
	answer: String,
}
impl StubUserInterface {
	pub fn new(answer: String) -> StubUserInterface {
		StubUserInterface { answer }
	}
}
impl UserInterface for StubUserInterface {
	fn get_user_answer<T: TryFrom<String> + InterfacerReturnType>(&self, _message: &str) -> T
	where <T as TryFrom<String>>::Error: std::fmt::Display {
		self.answer
			.clone()
			.try_into()
			.unwrap_or_else(|_err| panic!("PROGRAMMING ERROR: Invalid user answer, through StubUserInterface"))
	}

	fn send_message(&self, _message: &str) {}
}

pub struct AnyString {
	pub string: String,
}
impl InterfacerReturnType for AnyString {
	fn valid_answers() -> Option<&'static [&'static str]> {
		None
	}
}
impl From<String> for AnyString {
	fn from(string: String) -> Self {
		Self { string }
	}
}
pub struct SlashEnding {
	pub path: String,
}
impl InterfacerReturnType for SlashEnding {
	fn valid_answers() -> Option<&'static [&'static str]> {
		None
	}
}
impl TryFrom<String> for SlashEnding {
	type Error = &'static str;

	fn try_from(path: String) -> Result<SlashEnding, Self::Error> {
		if let Some('/') = path.chars().rev().next() {
			Ok(Self { path })
		}
		else {
			Err("The path must end with a forward slash \"/\"")
		}
	}
}
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum YesNo {
	Yes,
	No,
}
impl InterfacerReturnType for YesNo {
	fn valid_answers() -> Option<&'static [&'static str]> {
		Some(&["yes", "no"])
	}
}
impl TryFrom<String> for YesNo {
	type Error = &'static str;

	fn try_from(string: String) -> Result<YesNo, Self::Error> {
		Ok(match string.to_lowercase().as_str() {
			"yes" => YesNo::Yes,
			"no" => YesNo::No,
			_ => return Err("Only Yes or No are valid answers"),
		})
	}
}

pub enum YesNoAuto {
	Once(YesNo),
	Continued(YesNo),
}
impl InterfacerReturnType for YesNoAuto {
	fn valid_answers() -> Option<&'static [&'static str]> {
		Some(&["yes", "no", "contYes", "contNo"])
	}
}
impl TryFrom<String> for YesNoAuto {
	type Error = &'static str;

	fn try_from(string: String) -> Result<YesNoAuto, Self::Error> {
		if let Ok(yesno) = YesNo::try_from(string.clone()) {
			Ok(YesNoAuto::Once(yesno))
		}
		else if let Some(Ok(yesno_val)) = string.to_lowercase().strip_prefix("cont").map(|postfix| YesNo::try_from(postfix.to_owned())) {
			Ok(YesNoAuto::Continued(yesno_val))
		}
		else {
			Err("Valid answer are Yes/No/Contyes/Contno")
		}
	}
}
impl YesNoAuto {
	pub fn get_yesno_val(&self) -> YesNo {
		use YesNoAuto::*;
		match self {
			Once(val) => *val,
			Continued(val) => *val,
		}
	}
}
