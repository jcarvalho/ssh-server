package pt.jcarvalho.ssh.common.cipher;

public class CipherAES192 extends CipherAES {

	@Override
	public int keySize() {
		return 24;
	}

}
