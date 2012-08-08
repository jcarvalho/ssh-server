package pt.jcarvalho.ssh.common.kex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import pt.jcarvalho.ssh.common.exception.HashException;

public class DHSHA256 extends AbstractKeyExchange {

	@Override
	public byte[] hashOf(byte[] data) throws HashException {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			return digest.digest(data);
		} catch (NoSuchAlgorithmException e) {
			throw new HashException(e.getMessage());
		}
	}

	@Override
	public int hashSize() {
		return 32;
	}

}
