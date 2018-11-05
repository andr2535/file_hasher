use core::interfacer;
/// UserMessenger is named Messenger, because it
/// functions as an intermediary between the user and
/// the file_hasher modules.
pub struct UserMessenger {
	stdin: std::io::Stdin
}
impl UserMessenger {
	pub fn new() -> UserMessenger {
		let stdin = std::io::stdin();
		UserMessenger{stdin:stdin}
	}
}
impl interfacer::UserInterface for UserMessenger {
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