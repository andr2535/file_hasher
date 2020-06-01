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

/// UserMessenger is named Messenger, because it
/// functions as an intermediary between the user and
/// the file_hasher modules.
pub struct UserMessenger {
	stdin: std::io::Stdin
}
impl UserMessenger {
	pub fn new() -> UserMessenger {
		let stdin = std::io::stdin();
		UserMessenger{stdin}
	}
}

impl file_hasher_core::UserInterface for UserMessenger {
	fn get_user_answer(&self, message: &str) -> String {
		println!("{}", message);
		let mut input_string = String::new();
		self.stdin.read_line(&mut input_string).expect("Error reading user input");
		input_string.pop(); // Remove endline char.
		input_string
	}
	fn send_message(&self, message: &str) {
		println!("{}", message);
	}
}