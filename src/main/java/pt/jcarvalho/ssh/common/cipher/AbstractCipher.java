package pt.jcarvalho.ssh.common.cipher;

import pt.jcarvalho.ssh.common.exception.CipherException;


/**
 * Abstract class that represents a Cipher algorithm
 * @author joaocarvalho
 *
 */


public abstract class AbstractCipher {

	public abstract byte[] cipher(byte[] data) throws CipherException;
	
	public abstract byte[] decipher (byte[] data) throws CipherException;
	
	public abstract int cipherBlockSize();
	
	public abstract int keySize();
	
	public abstract void setIV(byte[] iv);
	
	public abstract void setKey(byte[] key) throws CipherException;

}
