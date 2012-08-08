package pt.jcarvalho.ssh.common;

public interface Encryptor {

    public byte[] cipher(byte[] data) throws CipherException;

    public byte[] decipher(byte[] data) throws CipherException;

    public int cipherBlockSize();

    public int keySize();

    public void setIV(byte[] iv);

    public void setKey(byte[] key) throws CipherException;

    // Exception

    public static class CipherException extends Exception {

	private static final long serialVersionUID = 4837847968960775937L;

	public CipherException(Exception e) {
	    super(e);
	}
    }

}
