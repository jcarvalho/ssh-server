package pt.jcarvalho.ssh.common.pki;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import pt.jcarvalho.ssh.common.exception.PKIException;

public class PKIConnector {

	static private ObjectInputStream ois;
	static private ObjectOutputStream oos;
	static private Socket socket;

	static private void connectToServer(String host) throws PKIException {
		try {
			socket = new Socket(host, 3333);
			ois = new ObjectInputStream(socket.getInputStream());
			oos = new ObjectOutputStream(socket.getOutputStream());
		} catch (IOException e) {
			throw new PKIException("PKI IO operations were unsuccessful");
		}
	}

	static public boolean sendRequest(PKIObject request, String host)
			throws PKIException {

		if (host == null) {
			host = "127.0.0.1";
		}

		connectToServer(host);

		Cipher cipher;
		SealedObject sealedRequest;
		SecretKeySpec keySpec = null;
		byte[] IV = new byte[16];
		byte[] key = { (byte) 0x8e, (byte) 0x2b, (byte) 0x14, (byte) 0xb9,
				(byte) 0xed, (byte) 0x52, (byte) 0x5c, (byte) 0xd3,
				(byte) 0x7f, (byte) 0xd3, (byte) 0x12, (byte) 0xd1,
				(byte) 0x06, (byte) 0xf5, (byte) 0x4f, (byte) 0x60,
				(byte) 0xf8, (byte) 0xf4, (byte) 0x52, (byte) 0x60,
				(byte) 0x87, (byte) 0x4e, (byte) 0xf9, (byte) 0xa8,
				(byte) 0x63, (byte) 0x72, (byte) 0x94, (byte) 0x37,
				(byte) 0x54, (byte) 0x22, (byte) 0x35, (byte) 0x34 };
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		System.err.println("Sending request: " + request);

		try {
			keySpec = new SecretKeySpec(key, "AES");
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
			sealedRequest = new SealedObject(request, cipher);

			oos.writeObject(sealedRequest);
			oos.flush();
			boolean reply = ois.readBoolean();

			socket.close();

			return reply;

		} catch (IOException e) {
			throw new PKIException("PKI IO operations were unsuccessful");
		} catch (GeneralSecurityException e) {
			throw new PKIException(
					"Secure connection to the PKI could not be established!");
		}
	}
}
