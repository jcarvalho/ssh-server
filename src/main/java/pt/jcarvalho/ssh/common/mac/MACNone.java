package pt.jcarvalho.ssh.common.mac;

/**
 * Class that implements the 'none' MAC.
 * @author joaocarvalho
 *
 */

public final class MACNone extends AbstractMAC {

	/**
	 * The MAC in this algorithm is always empty
	 */
	
	@Override
	public byte[] sign(byte[] key, byte[] data) {
		byte [] res = new byte[0];
		return res;
	}

	@Override
	public int macBytes() {
		return 0;
	}	

}
