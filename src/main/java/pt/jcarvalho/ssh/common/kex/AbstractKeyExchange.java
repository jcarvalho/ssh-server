package pt.jcarvalho.ssh.common.kex;

import pt.jcarvalho.ssh.common.exception.HashException;

public abstract class AbstractKeyExchange {
	
	public abstract byte[] hashOf(byte[] data) throws HashException;
	
	public abstract int hashSize();

}
