package pt.jcarvalho.ssh.common.kex;

import pt.jcarvalho.ssh.common.KeyExchange;

public class KexNone implements KeyExchange {

    @Override
    public byte[] hashOf(byte[] data) {
	return data;
    }

    @Override
    public int hashSize() {
	return -1;
    }

}
