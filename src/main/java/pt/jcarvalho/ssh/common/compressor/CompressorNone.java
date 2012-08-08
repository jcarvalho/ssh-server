package pt.jcarvalho.ssh.common.compressor;

import pt.jcarvalho.ssh.common.Compressor;

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
