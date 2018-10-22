mod e_d_list;
mod path_banlist;
mod interfacers;

use interfacers::UserInterface;

fn main() {
	let banlist = match path_banlist::PathBanlist::open(interfacers::UserMessenger::new()) {
		Ok(result) => result,
		Err(err) => {
			println!("Error opening banlist, Error = {}", err);
			return;
		}
	};
	let mut edlist = match e_d_list::EDList::open(interfacers::UserMessenger::new(), banlist) {
		Ok(list) => list,
		Err(err) => {
			println!("Error opening list, {}", err);
			return;
		}
	};


	let interfacer = interfacers::UserMessenger::new();

	loop {
		println!("Enter one of the following operations:");
		let answer = &interfacer.get_user_answer("Create\nVerify").to_lowercase();
		match answer.as_str() {
			"create" => {
				match edlist.create(&interfacer) {
					Ok(_res) => (),
					Err(err) => {
						println!("Error from edlist.create {}", err);
						return;
					}
				}
				break;
			},
			"verify" => {
				let error_list = edlist.verify(&interfacer);
				if error_list.len() > 0 {
					println!("Errors found:");
					for error in error_list {
						println!("{}", error);
					}
				}
				else {
					println!("No errors found!");
				}
				break;
			},
			_ => println!("Invalid value entered, try again!")
		}
	}

	match edlist.write_hash_file() {
		Ok(_ok) => (),
		Err(err) => println!("Error writing EDList to file, {}", err)
	}
}