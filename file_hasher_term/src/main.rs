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

mod term_interfacer;
use crate::term_interfacer::UserMessenger;

use structopt::StructOpt;

fn handle_error_list(error_list:Vec<impl std::error::Error>, prepend_message:&str, no_errors_message:Option<&str>) {
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

#[derive(StructOpt)]
#[structopt(name = "File Hasher", about = "A file hashing program")]
struct Opts { }

fn main() {
	let _opts = Opts::from_args();

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
			println!("Error opening list, err:\n{}", err);
			return;
		}
	};


	let interfacer = UserMessenger::new();

	loop {
		let mut break_bool = true;
		println!("Enter one of the following operations:");
		let answer = interfacer.get_user_answer("Create\nVerify\nVerifySub\nDelete\n\
		                                         Sort\nDuplicates\nRelativeChecksum\n\
		                                         Benchmark {optional byte argument}").to_lowercase();
		let mut answer = answer.split(' ');
		match answer.next().unwrap() {
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
			"relativechecksum" => edlist.relative_checksum(&interfacer),
			"benchmark" => {
				let argument = answer.next().map(|argument| usize::from_str_radix(argument, 10)).unwrap_or(Ok(1024*1024*1024*10));

				match argument {
					Ok(argument) => e_d_list::EDList::benchmark(&interfacer, argument),
					Err(_) => {
						println!("Invalid byte argument entered, must be a whole positive number");
						break_bool = false;
					}
				}
			},
			_ => {
				break_bool = false;
				println!("Invalid value entered, try again!");
			}
		}
		if break_bool {break;}
	}

	match edlist.write_hash_file() {
		Ok(()) => (),
		Err(err) => println!("Error writing EDList to file, {}", err)
	}
}