package pt.jcarvalho.ssh.server.channel.exception;

import java.io.IOException;

public class SecureChannelException extends IOException {

    /**
	 * 
	 */
    private static final long serialVersionUID = -8503962182979618401L;

    public SecureChannelException(String s) {
	super(s);
    }

}
