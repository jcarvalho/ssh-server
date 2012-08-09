package pt.jcarvalho.ssh.encryptor;

public class EncryptorAES192 extends EncryptorAES {

	@Override
	public int keySize() {
		return 24;
	}

}
