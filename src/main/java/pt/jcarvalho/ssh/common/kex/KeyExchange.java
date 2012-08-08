package pt.jcarvalho.ssh.common.kex;

public interface KeyExchange {

    public byte[] hashOf(byte[] data);

    public int hashSize();

}
