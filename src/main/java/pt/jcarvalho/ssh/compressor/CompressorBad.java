package pt.jcarvalho.ssh.compressor;

import java.util.Arrays;

import pt.jcarvalho.ssh.Compressor;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

public class CompressorBad implements Compressor {

    @Override
    public byte[] compress(byte[] data, byte[] iv) {
	return ByteArrayUtils.concat(data, data);
    }

    @Override
    public byte[] decompress(byte[] data, byte[] iv) {
	return Arrays.copyOf(data, data.length);
    }

}
