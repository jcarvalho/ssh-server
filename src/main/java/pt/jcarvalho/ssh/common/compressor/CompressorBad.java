package pt.jcarvalho.ssh.common.compressor;

import java.util.Arrays;

import pt.jcarvalho.ssh.common.Compressor;

import com.google.common.primitives.Bytes;

public class CompressorBad implements Compressor {

    @Override
    public byte[] compress(byte[] data, byte[] iv) {
	return Bytes.concat(data, data);
    }

    @Override
    public byte[] decompress(byte[] data, byte[] iv) {
	return Arrays.copyOf(data, data.length);
    }

}
