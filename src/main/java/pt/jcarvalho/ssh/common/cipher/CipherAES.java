package pt.jcarvalho.ssh.common.cipher;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import pt.jcarvalho.ssh.common.exception.CipherException;

public abstract class CipherAES extends AbstractCipher {
	
	IvParameterSpec iv;
	Cipher toCipher, toDecipher;
	
	public CipherAES() {
	}

	@Override
	public byte[] cipher(byte[] data) throws CipherException {
			return toCipher.update(data);
	}

	@Override
	public byte[] decipher(byte[] data) throws CipherException {
			return toDecipher.update(data);
	}
	
	public static CipherAES cipherWithSize(int size) {
		switch(size) {
		case 128:
			return new CipherAES128();
		case 192:
			return new CipherAES192();
		case 256:
			return new CipherAES256();
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

		} catch(GeneralSecurityException e) {
			throw new CipherException(e.getMessage());
		}
	}

}
