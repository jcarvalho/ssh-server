package pt.jcarvalho.ssh.encryptor;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import pt.jcarvalho.ssh.Encryptor;

public abstract class EncryptorAES implements Encryptor {

    IvParameterSpec iv;
    Cipher toCipher, toDecipher;

    public EncryptorAES() {
    }

    @Override
    public byte[] cipher(byte[] data) {
	return toCipher.update(data);
    }

    @Override
    public byte[] decipher(byte[] data) {
	return toDecipher.update(data);
    }

    public static EncryptorAES cipherWithSize(int size) {
	switch (size) {
	case 128:
	    return new EncryptorAES128();
	case 192:
	    return new EncryptorAES192();
	case 256:
	    return new EncryptorAES256();
	}
	return null;
    }

    @Override
    public int cipherBlockSize() {
	return 16;
    }

    @Override
    public void setIV(byte[] iv) {
	this.iv = new IvParameterSpec(iv, 0, cipherBlockSize());
    }

    @Override
    public void setKey(byte[] key) throws CipherException {
	try {
	    SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");

	    toCipher = Cipher.getInstance("AES/CBC/NoPadding");

	    toCipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

	    toDecipher = Cipher.getInstance("AES/CBC/NoPadding");

	    toDecipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

	} catch (GeneralSecurityException e) {
	    throw new CipherException(e);
	}
    }

}
