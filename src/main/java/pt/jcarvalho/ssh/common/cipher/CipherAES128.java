package pt.jcarvalho.ssh.common.cipher;

public class CipherAES128 extends CipherAES {

	@Override
	public int keySize() {
		return 16;
	}

}
