package pt.jcarvalho.ssh.compressor;

import pt.jcarvalho.ssh.Compressor;

public class CompressorNone implements Compressor {

    @Override
    public byte[] compress(byte[] data, byte[] iv) {
	return data;
    }

    @Override
    public byte[] decompress(byte[] data, byte[] iv) {
	return data;
    }

}
