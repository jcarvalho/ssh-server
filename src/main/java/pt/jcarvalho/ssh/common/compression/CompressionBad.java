package pt.jcarvalho.ssh.common.compression;

import pt.jcarvalho.ssh.common.util.ByteArrayUtils;

public class CompressionBad extends AbstractCompression {

	@Override
	public byte[] compress(byte[] data, byte[] iv) {
		return ByteArrayUtils.concat(data, data);
	}

	@Override
	public byte[] decompress(byte[] data, byte[] iv) {
		byte[] res = new byte[data.length / 2];
		System.arraycopy(data, 0, res, 0, data.length / 2);
		return res;
	}

}
