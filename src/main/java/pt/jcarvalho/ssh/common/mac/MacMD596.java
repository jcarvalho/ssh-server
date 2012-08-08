package pt.jcarvalho.ssh.common.mac;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import pt.jcarvalho.ssh.common.exception.MacException;

public class MacMD596 extends AbstractMAC {

	@Override
	public byte[] sign(byte[] key, byte[] data) throws MacException {
		try {
		SecretKey skey = new SecretKeySpec(key, "HmacMD5");
		Mac m = Mac.getInstance("HmacMD5");
		m.init(skey);
		m.update(data);
		byte[] val = new byte[12];
		System.arraycopy(m.doFinal(), 0, val, 0, 12);
		return val;
		} catch(GeneralSecurityException e) {
			throw new MacException(e.getMessage());
		}
	}

	@Override
	public int macBytes() {
		return 12;
	}


}
