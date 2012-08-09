package pt.jcarvalho.ssh.mac;

import pt.jcarvalho.ssh.MAC;

/**
 * Class that implements the 'none' MAC.
 * 
 * @author joaocarvalho
 * 
 */

public final class MACNone implements MAC {

    /**
     * The MAC in this algorithm is always empty
     */

    @Override
    public byte[] generateCode(byte[] data) {
	return new byte[0];
    }

    @Override
    public int macBytes() {
	return 0;
    }

    @Override
    public void setKey(byte[] key) {
	// No keys on this one...
    }

}
