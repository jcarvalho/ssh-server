package pt.jcarvalho.ssh.common.encryptor;

public class EncryptorAES128 extends EncryptorAES {

	@Override
	public int keySize() {
		return 16;
	}

}
