
/// file_element is a struct for an element that is a file
/// it needs to know the time the file was changed, and the
/// Hashed value of the files content.
struct FileElement {
	someType timechanged,
	String file_hash
}

/// link_element is a struct for an element that is a 
/// symbolic link, it only needs a target, which we call
/// link_path here.
struct LinkElement {
	String link_path
}

/// EDElementType is used to manage whether we are storing
/// a file or a symbolic link.
enum EDElementType {
	file(FileElement),
	link(LinkElement)
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
