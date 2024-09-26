package swiss.dasch.plugins.serviceusers;

public class UserAlreadyExistsException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 7897898800703339408L;

	public final String userId;

	public UserAlreadyExistsException(String message, String userId) {
		super(message);
		this.userId = userId;
	}

}
