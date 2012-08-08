package pt.jcarvalho.ssh.common.kex;

import pt.jcarvalho.ssh.common.exception.HashException;

/**
 * 
 * Key Exchange that performs no hashing
 * 
 * @author joaocarvalho
 *
 */

public class KexNone extends AbstractKeyExchange {

	@Override
	public byte[] hashOf(byte[] data) throws HashException {
		return data;
	}

	@Override
	public int hashSize() {
		return -1;
	}
	
	

}
