package pt.jcarvalho.ssh.common;

import pt.jcarvalho.ssh.common.exception.CipherException;

public interface Encryptor {

    public byte[] cipher(byte[] data) throws CipherException;

    public byte[] decipher(byte[] data) throws CipherException;

    public int cipherBlockSize();

    public int keySize();

    public void setIV(byte[] iv);

    public void setKey(byte[] key) throws CipherException;

}
