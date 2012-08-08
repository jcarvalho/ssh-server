package pt.jcarvalho.ssh.common.mac;

import pt.jcarvalho.ssh.common.exception.MacException;

/**
 * Abstract class that represents a message authentication
 * code provider
 * 
 * @author joaocarvalho
 *
 */

public abstract class AbstractMAC {
	
	public abstract byte[] sign(byte[] key, byte[] data) throws MacException;
	
	public abstract int macBytes();

}
