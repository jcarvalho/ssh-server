package pt.jcarvalho.ssh.common.cipher;

public class CipherAES256 extends CipherAES {

	@Override
	public int keySize() {
		return 32;
	}

}
