use super::*;

/// BanlistAsker implements the Answer trait of path_banlist.
/// It implements it in a way, so that the user must input
/// the answer into stdin
pub struct BanlistAsker {
	stdin: std::io::Stdin
}
impl BanlistAsker {
	pub fn new() -> BanlistAsker {
		let stdin = std::io::stdin();
		BanlistAsker{stdin:stdin}
	}
}
impl path_banlist::Answer for BanlistAsker {
	fn get_answer(&self, message:String) -> bool {
		loop{
			print!("{} ", message);
			println!("YES/NO");
			let input_string = &mut String::new();
			self.stdin.read_line(input_string).expect("Error reading user input");
			input_string.pop(); // Remove endline char.
			if input_string == "YES" {
				return true;
			}
			else if input_string == "NO" {
				return false;
			}
		}
	}
}

pub struct EDListAsker {
	stdin: std::io::Stdin
}
impl EDListAsker {
	pub fn new() -> EDListAsker {
		let stdin = std::io::stdin();
		EDListAsker{stdin:stdin}
	}
}
impl e_d_list::EDListInterface for EDListAsker {
	fn get_user_answer(&self, message: &str) -> String {
		println!("{}", message);
		let mut input_string = String::new();
		self.stdin.read_line(&mut input_string).expect("Error reading user input");
		input_string.pop(); // Remove endline char.
		return input_string;
	}
	fn send_message(&self, message: &str) {
		println!("{}", message);
	}
}