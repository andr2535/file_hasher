mod e_d_list;

fn main() {
    println!("Hello, world!");
    let sdf = vec![3,2,4];
    use e_d_list::e_d_element::EDElement;
    let element = match EDElement::from_file(String::from("test")) {
        Ok(element) => element,
        Err(error) => return
    };
    println!("{:?}", element);
}
