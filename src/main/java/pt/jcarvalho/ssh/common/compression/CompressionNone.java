package pt.jcarvalho.ssh.common.compression;

/**
 * Compression that does not modify the data
 * @author joaocarvalho
 *
 */

public class CompressionNone extends AbstractCompression {

	@Override
	public byte[] compress(byte[] data, byte[] iv) {
		return data;
	}

	@Override
	public byte[] decompress(byte[] data, byte[] iv) {
		return data;
	}

}
