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

pub trait UserInterface {
	/// Gives the message to the user, and returns
	/// the users answer to the caller without the
	/// endline character.
	fn get_user_answer(&self, message: &str) -> String;
	/// Gives a message, that should be shown to the user,
	/// but the user can't reply to it.
	fn send_message(&self, message: &str);
}
pub struct StubUserInterface {
	answer: String
}
impl StubUserInterface {
	pub fn new(answer: String) -> StubUserInterface {
		StubUserInterface{answer}
	}
}
impl UserInterface for StubUserInterface {
	fn get_user_answer(&self, _message: &str) -> String {
		self.answer.clone()
	}
	fn send_message(&self, _message: &str) { }
}