package pt.jcarvalho.ssh.common;

public interface KeyExchange {

    public byte[] hashOf(byte[] data);

    public int hashSize();

}
