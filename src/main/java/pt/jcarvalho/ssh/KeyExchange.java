package pt.jcarvalho.ssh;

public interface KeyExchange {

    public byte[] hashOf(byte[] data);

    public int hashSize();

}
