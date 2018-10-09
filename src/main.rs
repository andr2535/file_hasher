mod e_d_list;
mod path_banlist;
mod interfacers;

fn main() {
	use e_d_list::e_d_element::EDElement;
	let element = match EDElement::from_path(String::from("ln")) {
		Ok(element) => element,
		Err(error) => {println!("{}", error); return;}
	};
	println!("{:?}", element.to_string());
	println!("{:?}", EDElement::from_str(&element.to_string()).unwrap());
	println!("{:?}", element.to_string());

	let result = match path_banlist::PathBanlist::open(interfacers::BanlistAsker::new()) {
		Ok(result) => result,
		Err(err) => {
			println!("Error opening banlist, Error = {}", err);
			return;
		}
	};
	println!("result = {:?}", result);
}