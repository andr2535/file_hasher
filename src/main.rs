mod e_d_list;
mod path_banlist;
mod interfacers;

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
	match edlist.create(interfacers::UserMessenger::new()) {
		Ok(_res) => (),
		Err(err) => {
			println!("Error from edlist.create {}", err);
			return;
		}
	}
	match edlist.write_hash_file() {
		Ok(_ok) => (),
		Err(err) => println!("Error writing EDList to file, {}", err)
	}
}