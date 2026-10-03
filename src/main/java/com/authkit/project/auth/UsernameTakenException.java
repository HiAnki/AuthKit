package com.authkit.project.auth;

/** An account with this username already exists. */
public class UsernameTakenException extends RuntimeException {

	public UsernameTakenException() {
		super(null, null, false, false);
	}

}
