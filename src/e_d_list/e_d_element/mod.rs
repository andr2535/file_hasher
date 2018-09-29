struct file_element {
	someType timechanged,
	String file_hash
}
/// link_element is a struct for an element that is a 
/// symbolic link, it only needs a target, which we call
/// link_path here.
struct link_element {
	String link_path
}
enum EDElementType {
	file(file_element),
	link(link_element)
}

/// EDElement, a shorthand for Error-detect-element
/// It should be used by a EDList object, for safely storing
/// metadata about files and links.
/// 
/// path is used for storing the path for the element
/// 
/// element_type_fields can store either information about a
/// file, or it can store information about a link.
/// 
/// element_hash contains a hash value of all the fields in
/// the EDElement object.
pub struct EDElement {
	String path,
	EDElementType element_type_fields,
	vec<u64>?? element_hash
}
impl EDElement {
	
}
