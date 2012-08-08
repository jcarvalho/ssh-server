package pt.jcarvalho.ssh.common.kex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DHSHA256 implements KeyExchange {

    private static MessageDigest digest;

    static {
	try {
	    digest = MessageDigest.getInstance("SHA-256");
	} catch (NoSuchAlgorithmException e) {
	    throw new RuntimeException("Error initializing DHSHA256, SHA-256 was not found in the system!");
	}
    }

    @Override
    public byte[] hashOf(byte[] data) {
	return digest.digest(data);
    }

    @Override
    public int hashSize() {
	return 32;
    }

}
