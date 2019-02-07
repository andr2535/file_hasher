mod core;
use crate::core::*;
use crate::core::interfacer::UserInterface;

mod term_interfacer;
use crate::term_interfacer::UserMessenger;

fn handle_error_list(error_list:Vec<String>, prepend_message:&str, no_errors_message:Option<&str>) {
	if !error_list.is_empty() {
		let length = error_list.len();
		let length_width = length.to_string().chars().count();
		println!("{}", prepend_message);
		for (counter, error) in error_list.iter().enumerate() {
			println!("Error {:0width$} of {}: {}", counter + 1, length, error, width=length_width);
		}
	}
	else if let Some(no_errors_message) = no_errors_message {
		println!("{}", no_errors_message);
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
		let answer = interfacer.get_user_answer("Create\nVerify\nVerifySub\nDelete\nSort\nDuplicates").to_lowercase();
		match answer.as_str() {
			"create" =>
				match edlist.create(&interfacer) {
					Ok(err_list) => {
						handle_error_list(err_list, "There were errors during this create operation:", None);
					},
					Err(err) => {
						println!("Error from edlist.create {}", err);
						return;
					}
				},
			"verify" => handle_error_list(edlist.verify(None, &interfacer), "Errors found:", Some("No errors found!")),
			"verifysub" => {
				let prefix = interfacer.get_user_answer("Enter your path prefix");
				handle_error_list(edlist.verify(Some(&prefix), &interfacer), "Errors found:", Some("No errors found!"));
			},
			"delete" => edlist.delete(&interfacer),
			"sort" => edlist.sort(),
			"duplicates" => edlist.find_duplicates(&interfacer),
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