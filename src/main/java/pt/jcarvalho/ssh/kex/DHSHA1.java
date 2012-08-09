package pt.jcarvalho.ssh.kex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import pt.jcarvalho.ssh.KeyExchange;

public class DHSHA1 implements KeyExchange {

    private static MessageDigest digest;

    static {
	try {
	    digest = MessageDigest.getInstance("SHA-1");
	} catch (NoSuchAlgorithmException e) {
	    throw new RuntimeException("Error initializing DHSHA1, SHA-1 was not found in the system!");
	}
    }

    @Override
    public byte[] hashOf(byte[] data) {
	return digest.digest(data);
    }

    @Override
    public int hashSize() {
	return 20;
    }

}
