pub mod e_d_element;

use self::e_d_element::EDElement;

const HASH_OUTPUT_LENGTH: usize = 32;

#[derive(Debug)]
/// EDList
struct EDList {
	element_list: Vec<EDElement>,
	checksum: [u8; HASH_OUTPUT_LENGTH]
}
impl EDList {

}