package pt.jcarvalho.ssh.common.compression;

/**
 * Abstract class that represents a compression algorithm
 * @author joaocarvalho
 *
 */

public abstract class AbstractCompression {
	
	/**
	 * Some algorithms may require more than just the data
	 * in order to perform the compression. In those cases,
	 * the parameter 'iv' should be used.
	 */
	
	public abstract byte[] compress(byte[] data, byte[] iv);
	
	public abstract byte[] decompress(byte[] data, byte[] iv);


}
