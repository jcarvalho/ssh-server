package pt.jcarvalho.ssh.common.encryptor;

public class EncryptorAES256 extends EncryptorAES {

	@Override
	public int keySize() {
		return 32;
	}

}
