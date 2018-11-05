pub trait UserInterface {
	/// Gives the message to the user, and returns
	/// the users answer to the caller without the
	/// endline character.
	fn get_user_answer(&self, message: &str) -> String;
	/// Gives a message, that should be shown to the user,
	/// but the user can't reply to it.
	fn send_message(&self, message: &str);
}