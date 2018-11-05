mod core;
use core::*;
use core::interfacer::UserInterface;

mod term_interfacer;
use term_interfacer::UserMessenger;

fn handle_verify_error_list(error_list:Vec<String>) {
	if error_list.len() > 0 {
		println!("Errors found:");
		for error in error_list {
			println!("{}", error);
		}
	}
	else {
		println!("No errors found!");
	}
}

fn main() {
	let banlist = match path_banlist::PathBanlist::open(UserMessenger::new()) {
		Ok(result) => result,
		Err(err) => {
			println!("Error opening banlist, Error = {}", err);
			return;
		}
	};
	let mut edlist = match e_d_list::EDList::open(UserMessenger::new(), banlist) {
		Ok(list) => list,
		Err(err) => {
			println!("Error opening list, {}", err);
			return;
		}
	};


	let interfacer = UserMessenger::new();

	loop {
		let mut break_bool = true;
		println!("Enter one of the following operations:");
		let answer = &interfacer.get_user_answer("Create\nVerify\nVerifySub\nDelete\nSort\nDuplicates").to_lowercase();
		match answer.as_str() {
			"create" => {
				match edlist.create(&interfacer) {
					Ok(_res) => (),
					Err(err) => {
						println!("Error from edlist.create {}", err);
						return;
					}
				}
			},
			"verify" => {
				handle_verify_error_list(edlist.verify(None, &interfacer));
				
			},
			"verifysub" => {
				let prefix = interfacer.get_user_answer("Enter your path prefix");
				handle_verify_error_list(edlist.verify(Some(prefix), &interfacer));
			},
			"delete" => {
				edlist.delete(&interfacer);
			},
			"sort" => {
				edlist.sort();
			},
			"duplicates" => {
				edlist.find_duplicates(&interfacer);
			},
			_ => {
				break_bool = false;
				println!("Invalid value entered, try again!");
			}
		}
		if break_bool {break;}
	}

	match edlist.write_hash_file() {
		Ok(_ok) => (),
		Err(err) => println!("Error writing EDList to file, {}", err)
	}
}