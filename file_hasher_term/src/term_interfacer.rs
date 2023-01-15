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

use file_hasher_core::*;

/// UserMessenger is named Messenger, because it
/// functions as an intermediary between the user and
/// the file_hasher modules.
pub struct UserMessenger {
	stdin: std::io::Stdin,
}
impl UserMessenger {
	pub fn new() -> UserMessenger {
		let stdin = std::io::stdin();
		UserMessenger { stdin }
	}
}

impl UserInterface for UserMessenger {
	fn get_user_answer<T: InterfacerReturnType>(&self, message: &str) -> T
	where <T as TryFrom<String>>::Error: std::fmt::Display {
		let mut input_string = String::new();
		loop {
			print!("{} ", message);
			if let Some(valid_values) = T::valid_answers() {
				let mut print_string = String::new();
				for value in valid_values {
					print_string.push_str(value);
					print_string.push('/');
				}
				print_string.pop();
				print!("{}", print_string);
			}
			println!();
			self.stdin.read_line(&mut input_string).expect("Error reading user input");

			match T::try_from(input_string.trim_end().to_string()) {
				Ok(res) => return res,
				Err(err) => println!("{}", err),
			}

			input_string.clear();
		}
	}

	fn send_message(&self, message: &str) {
		println!("{}", message);
	}
}
