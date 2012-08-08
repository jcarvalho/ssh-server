package pt.jcarvalho.ssh.common.cipher;

import pt.jcarvalho.ssh.common.exception.CipherException;

/**
 * Cipher that does no modification to the data
 * 
 * 
 * @author joaocarvalho
 *
 */

public class CipherNone extends AbstractCipher {

	@Override
	public byte[] cipher(byte[] data) {
		return data;
	}

	@Override
	public byte[] decipher(byte[] data) {
		return data;
	}

	@Override
	public int cipherBlockSize() {
		return 1;
	}

	@Override
	public void setIV(byte[] iv) {		
	}

	@Override
	public int keySize() {
		return 0;
	}

	@Override
	public void setKey(byte[] key) throws CipherException {		
	}

}
