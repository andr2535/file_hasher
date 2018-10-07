mod e_d_list;
mod path_banlist;

fn main() {
	use e_d_list::e_d_element::EDElement;
	let element = match EDElement::from_path(String::from("ln")) {
		Ok(element) => element,
		Err(error) => {println!("{}", error); return;}
	};
	println!("{:?}", element.to_string());
	println!("{:?}", EDElement::from_str(&element.to_string()).unwrap());
	println!("{:?}", element.to_string());
	use path_banlist::PathBanlist;

	let result = match PathBanlist::open() {
		Ok(result) => result,
		Err(err) => {
			println!("Error opening banlist, Error = {}", err);
			println!("Creating new banlist");
			match PathBanlist::new() {
				Ok(result) => result,
				Err(err) => panic!(err)
			}
		}
	};
	println!("result = {:?}", result);
}
