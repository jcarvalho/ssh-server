package pt.jcarvalho.ssh.common;

public interface Compressor {

    public byte[] compress(byte[] data, byte[] iv);

    public byte[] decompress(byte[] data, byte[] iv);

}
