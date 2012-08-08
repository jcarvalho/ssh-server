package pt.jcarvalho.ssh.server.channel.ssh.packet.kex;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.common.adt.MPInt;
import pt.jcarvalho.ssh.common.adt.SSHString;
import pt.jcarvalho.ssh.common.util.ByteArrayUtils;
import pt.jcarvalho.ssh.common.util.Security;
import pt.jcarvalho.ssh.server.channel.ssh.KeyInformation;
import pt.jcarvalho.ssh.server.channel.ssh.packet.Disconnect;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacket;

public class DHKexReply extends SSHPacket {

    public DHKexReply(KeyInformation keyInformation) {
	super(keyInformation);
    }

    @Override
    public byte[] binaryRepresentation() {
	try {

	    byte[] pBytes;

	    if (keyInformation.group == 1) {
		byte[] b = { (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xc9, (byte) 0x0f, (byte) 0xda, (byte) 0xa2, (byte) 0x21, (byte) 0x68,
			(byte) 0xc2, (byte) 0x34, (byte) 0xc4, (byte) 0xc6, (byte) 0x62, (byte) 0x8b, (byte) 0x80, (byte) 0xdc,
			(byte) 0x1c, (byte) 0xd1, (byte) 0x29, (byte) 0x02, (byte) 0x4e, (byte) 0x08, (byte) 0x8a, (byte) 0x67,
			(byte) 0xcc, (byte) 0x74, (byte) 0x02, (byte) 0x0b, (byte) 0xbe, (byte) 0xa6, (byte) 0x3b, (byte) 0x13,
			(byte) 0x9b, (byte) 0x22, (byte) 0x51, (byte) 0x4a, (byte) 0x08, (byte) 0x79, (byte) 0x8e, (byte) 0x34,
			(byte) 0x04, (byte) 0xdd, (byte) 0xef, (byte) 0x95, (byte) 0x19, (byte) 0xb3, (byte) 0xcd, (byte) 0x3a,
			(byte) 0x43, (byte) 0x1b, (byte) 0x30, (byte) 0x2b, (byte) 0x0a, (byte) 0x6d, (byte) 0xf2, (byte) 0x5f,
			(byte) 0x14, (byte) 0x37, (byte) 0x4f, (byte) 0xe1, (byte) 0x35, (byte) 0x6d, (byte) 0x6d, (byte) 0x51,
			(byte) 0xc2, (byte) 0x45, (byte) 0xe4, (byte) 0x85, (byte) 0xb5, (byte) 0x76, (byte) 0x62, (byte) 0x5e,
			(byte) 0x7e, (byte) 0xc6, (byte) 0xf4, (byte) 0x4c, (byte) 0x42, (byte) 0xe9, (byte) 0xa6, (byte) 0x37,
			(byte) 0xed, (byte) 0x6b, (byte) 0x0b, (byte) 0xff, (byte) 0x5c, (byte) 0xb6, (byte) 0xf4, (byte) 0x06,
			(byte) 0xb7, (byte) 0xed, (byte) 0xee, (byte) 0x38, (byte) 0x6b, (byte) 0xfb, (byte) 0x5a, (byte) 0x89,
			(byte) 0x9f, (byte) 0xa5, (byte) 0xae, (byte) 0x9f, (byte) 0x24, (byte) 0x11, (byte) 0x7c, (byte) 0x4b,
			(byte) 0x1f, (byte) 0xe6, (byte) 0x49, (byte) 0x28, (byte) 0x66, (byte) 0x51, (byte) 0xec, (byte) 0xe6,
			(byte) 0x53, (byte) 0x81, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff };
		pBytes = b;
	    } else {
		byte[] b = { (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xc9, (byte) 0x0f, (byte) 0xda, (byte) 0xa2, (byte) 0x21, (byte) 0x68,
			(byte) 0xc2, (byte) 0x34, (byte) 0xc4, (byte) 0xc6, (byte) 0x62, (byte) 0x8b, (byte) 0x80, (byte) 0xdc,
			(byte) 0x1c, (byte) 0xd1, (byte) 0x29, (byte) 0x02, (byte) 0x4e, (byte) 0x08, (byte) 0x8a, (byte) 0x67,
			(byte) 0xcc, (byte) 0x74, (byte) 0x02, (byte) 0x0b, (byte) 0xbe, (byte) 0xa6, (byte) 0x3b, (byte) 0x13,
			(byte) 0x9b, (byte) 0x22, (byte) 0x51, (byte) 0x4a, (byte) 0x08, (byte) 0x79, (byte) 0x8e, (byte) 0x34,
			(byte) 0x04, (byte) 0xdd, (byte) 0xef, (byte) 0x95, (byte) 0x19, (byte) 0xb3, (byte) 0xcd, (byte) 0x3a,
			(byte) 0x43, (byte) 0x1b, (byte) 0x30, (byte) 0x2b, (byte) 0x0a, (byte) 0x6d, (byte) 0xf2, (byte) 0x5f,
			(byte) 0x14, (byte) 0x37, (byte) 0x4f, (byte) 0xe1, (byte) 0x35, (byte) 0x6d, (byte) 0x6d, (byte) 0x51,
			(byte) 0xc2, (byte) 0x45, (byte) 0xe4, (byte) 0x85, (byte) 0xb5, (byte) 0x76, (byte) 0x62, (byte) 0x5e,
			(byte) 0x7e, (byte) 0xc6, (byte) 0xf4, (byte) 0x4c, (byte) 0x42, (byte) 0xe9, (byte) 0xa6, (byte) 0x37,
			(byte) 0xed, (byte) 0x6b, (byte) 0x0b, (byte) 0xff, (byte) 0x5c, (byte) 0xb6, (byte) 0xf4, (byte) 0x06,
			(byte) 0xb7, (byte) 0xed, (byte) 0xee, (byte) 0x38, (byte) 0x6b, (byte) 0xfb, (byte) 0x5a, (byte) 0x89,
			(byte) 0x9f, (byte) 0xa5, (byte) 0xae, (byte) 0x9f, (byte) 0x24, (byte) 0x11, (byte) 0x7c, (byte) 0x4b,
			(byte) 0x1f, (byte) 0xe6, (byte) 0x49, (byte) 0x28, (byte) 0x66, (byte) 0x51, (byte) 0xec, (byte) 0xe4,
			(byte) 0x5b, (byte) 0x3d, (byte) 0xc2, (byte) 0x00, (byte) 0x7c, (byte) 0xb8, (byte) 0xa1, (byte) 0x63,
			(byte) 0xbf, (byte) 0x05, (byte) 0x98, (byte) 0xda, (byte) 0x48, (byte) 0x36, (byte) 0x1c, (byte) 0x55,
			(byte) 0xd3, (byte) 0x9a, (byte) 0x69, (byte) 0x16, (byte) 0x3f, (byte) 0xa8, (byte) 0xfd, (byte) 0x24,
			(byte) 0xcf, (byte) 0x5f, (byte) 0x83, (byte) 0x65, (byte) 0x5d, (byte) 0x23, (byte) 0xdc, (byte) 0xa3,
			(byte) 0xad, (byte) 0x96, (byte) 0x1c, (byte) 0x62, (byte) 0xf3, (byte) 0x56, (byte) 0x20, (byte) 0x85,
			(byte) 0x52, (byte) 0xbb, (byte) 0x9e, (byte) 0xd5, (byte) 0x29, (byte) 0x07, (byte) 0x70, (byte) 0x96,
			(byte) 0x96, (byte) 0x6d, (byte) 0x67, (byte) 0x0c, (byte) 0x35, (byte) 0x4e, (byte) 0x4a, (byte) 0xbc,
			(byte) 0x98, (byte) 0x04, (byte) 0xf1, (byte) 0x74, (byte) 0x6c, (byte) 0x08, (byte) 0xca, (byte) 0x18,
			(byte) 0x21, (byte) 0x7c, (byte) 0x32, (byte) 0x90, (byte) 0x5e, (byte) 0x46, (byte) 0x2e, (byte) 0x36,
			(byte) 0xce, (byte) 0x3b, (byte) 0xe3, (byte) 0x9e, (byte) 0x77, (byte) 0x2c, (byte) 0x18, (byte) 0x0e,
			(byte) 0x86, (byte) 0x03, (byte) 0x9b, (byte) 0x27, (byte) 0x83, (byte) 0xa2, (byte) 0xec, (byte) 0x07,
			(byte) 0xa2, (byte) 0x8f, (byte) 0xb5, (byte) 0xc5, (byte) 0x5d, (byte) 0xf0, (byte) 0x6f, (byte) 0x4c,
			(byte) 0x52, (byte) 0xc9, (byte) 0xde, (byte) 0x2b, (byte) 0xcb, (byte) 0xf6, (byte) 0x95, (byte) 0x58,
			(byte) 0x17, (byte) 0x18, (byte) 0x39, (byte) 0x95, (byte) 0x49, (byte) 0x7c, (byte) 0xea, (byte) 0x95,
			(byte) 0x6a, (byte) 0xe5, (byte) 0x15, (byte) 0xd2, (byte) 0x26, (byte) 0x18, (byte) 0x98, (byte) 0xfa,
			(byte) 0x05, (byte) 0x10, (byte) 0x15, (byte) 0x72, (byte) 0x8e, (byte) 0x5a, (byte) 0x8a, (byte) 0xac,
			(byte) 0xaa, (byte) 0x68, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff };
		pBytes = b;
	    }

	    byte[] gBytes = { (byte) 0x02 };

	    keyInformation.p = new MPInt(pBytes);
	    keyInformation.g = new MPInt(gBytes);

	    byte[] V_C = SSHString.byteArrayOf(keyInformation.clientString);
	    byte[] V_S = SSHString.byteArrayOf(keyInformation.serverString);

	    /**
	     * Generate the Shared Secret from Diffie-Hellman Generate the 'f'
	     * value to send to the client.
	     */

	    DHParameterSpec dhParams = new DHParameterSpec(keyInformation.p.toBigInt(), keyInformation.g.toBigInt());
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");

	    keyGen.initialize(dhParams, new SecureRandom());
	    KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH");

	    KeyPair aPair = keyGen.generateKeyPair();

	    DHPublicKey serverPub = (DHPublicKey) aPair.getPublic();

	    keyInformation.f = new MPInt(serverPub.getY());

	    aKeyAgree.init(aPair.getPrivate());

	    PublicKey publicKey;

	    DHPublicKeySpec dhKeySpec = new DHPublicKeySpec(keyInformation.e.toBigInt(), keyInformation.p.toBigInt(),
		    keyInformation.g.toBigInt());
	    KeyFactory keyFact = KeyFactory.getInstance("DH");
	    publicKey = keyFact.generatePublic(dhKeySpec);

	    aKeyAgree.doPhase(publicKey, true);

	    byte[] secret = aKeyAgree.generateSecret();

	    keyInformation.K = new MPInt(secret);

	    /**
	     * Generate the blob with the Host Key, encoded in ssh-rsa
	     */

	    keyInformation.K_S = ByteArrayUtils.concatAll(SSHString.byteArrayOf("ssh-rsa"),
		    MPInt.bytesOf(Security.getRsaPub().getPublicExponent()), MPInt.bytesOf(Security.getRsaPub().getModulus()));

	    /**
	     * Generate H
	     */

	    byte[] toHash = ByteArrayUtils.concatAll(V_C, V_S, keyInformation.I_C, keyInformation.I_S,
		    SSHString.byteArrayOf(keyInformation.K_S), keyInformation.e.toByteArray(), keyInformation.f.toByteArray(),
		    keyInformation.K.toByteArrayWithLeadingZeros());

	    keyInformation.H = keyInformation.kex.hashOf(toHash);

	    if (keyInformation.sessionId == null) {
		keyInformation.sessionId = keyInformation.H;
	    }

	    /**
	     * Sign H
	     */

	    byte[] finalHash = SSHString.byteArrayOf(Security.Sign(Security.getRsaPriv(), keyInformation.H));

	    SSHString s = new SSHString(ByteArrayUtils.concat(SSHString.byteArrayOf("ssh-rsa"), finalHash));

	    /**
	     * Pack it, and send to client
	     */

	    byte[] code = { SSHNumbers.SSH_MSG_KEXDH_REPLY };

	    return ByteArrayUtils.concatAll(code, SSHString.byteArrayOf(keyInformation.K_S), keyInformation.f.toByteArray(),
		    s.toByteArray());
	} catch (Exception e) {
	    e.printStackTrace();
	    return new Disconnect(e.getMessage(), SSHNumbers.SSH_DISCONNECT_KEY_EXCHANGE_FAILED).binaryRepresentation();
	}

    }

    @Override
    public void initWithData(byte[] data) {
    }

    @Override
    public void process() {

    }

    @Override
    public SSHPacket nextPacket() {
	return null;
    }

}
