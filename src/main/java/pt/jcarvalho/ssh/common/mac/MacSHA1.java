package pt.jcarvalho.ssh.common.mac;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import pt.jcarvalho.ssh.common.exception.MacException;

public class MacSHA1 extends AbstractMAC {

	@Override
	public byte[] sign(byte[] key, byte[] data) throws MacException {
		try {
		SecretKey skey = new SecretKeySpec(key, "HmacSHA1");
		Mac m = Mac.getInstance("HmacSHA1");
		m.init(skey);
		m.update(data);
		return m.doFinal();
		} catch(GeneralSecurityException e) {
			throw new MacException(e.getMessage());
		}
	}

	@Override
	public int macBytes() {
		try {
			Mac m = Mac.getInstance("HmacSHA1");
			return m.getMacLength();
		} catch (NoSuchAlgorithmException e) {
			return 0;
		}
	}


}
