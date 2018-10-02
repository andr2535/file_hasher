mod e_d_list;

fn main() {
	let sdf = vec![3,2,4];
	use e_d_list::e_d_element::EDElement;
	let element = match EDElement::from_path(String::from("ln")) {
		Ok(element) => element,
		Err(error) => {println!("{}", error); return;}
	};
	println!("{:?}", element);
	println!("{:?}", EDElement::from_str(&element.to_str()).unwrap());
	println!("{:?}", element.to_str());
}
