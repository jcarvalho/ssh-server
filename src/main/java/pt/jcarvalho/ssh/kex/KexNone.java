package pt.jcarvalho.ssh.kex;

import pt.jcarvalho.ssh.KeyExchange;

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
