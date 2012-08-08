package pt.jcarvalho.ssh.server.channel.exception;

public class LargePayloadException extends SecureChannelException {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7192886112979501003L;

	public LargePayloadException(String s) {
		super(s);
	}

}
