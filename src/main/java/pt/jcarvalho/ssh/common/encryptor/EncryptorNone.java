package pt.jcarvalho.ssh.common.encryptor;

import pt.jcarvalho.ssh.common.Encryptor;

/**
 * Cipher that does no modification to the data
 * 
 * 
 * @author joaocarvalho
 * 
 */

public class EncryptorNone implements Encryptor {

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
