package pt.jcarvalho.ssh.common.encryptor;

public class EncryptorAES192 extends EncryptorAES {

	@Override
	public int keySize() {
		return 24;
	}

}
