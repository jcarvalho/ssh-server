package pt.jcarvalho.ssh.encryptor;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import pt.jcarvalho.ssh.Encryptor;

public class Encryptor3DES implements Encryptor {

    IvParameterSpec iv;
    Cipher toCipher, toDecipher;

    public Encryptor3DES() {
    }

    @Override
    public byte[] cipher(byte[] data) {
	return toCipher.update(data);
    }

    @Override
    public byte[] decipher(byte[] data) {
	return toDecipher.update(data);
    }

    @Override
    public int cipherBlockSize() {
	return 8;
    }

    @Override
    public void setIV(byte[] iv) {
	this.iv = new IvParameterSpec(iv, 0, cipherBlockSize());
    }

    @Override
    public int keySize() {
	return 21;
    }

    @Override
    public void setKey(byte[] key) throws CipherException {
	try {
	    SecretKeySpec skeySpec = new SecretKeySpec(key, "DESede");
	    toCipher = Cipher.getInstance("DESede/CBC/NoPadding");

	    toCipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

	    toDecipher = Cipher.getInstance("DESede/CBC/NoPadding");
	    toDecipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

	} catch (GeneralSecurityException e) {
	    throw new CipherException(e);
	}

    }

}
