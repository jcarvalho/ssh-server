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

public class DHGexReply extends SSHPacket {

    public DHGexReply(KeyInformation keyInformation) {
	super(keyInformation);
    }

    @Override
    public byte[] binaryRepresentation() {

	try {

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

	    byte[] toHash;

	    if (keyInformation.compatMode) {
		toHash = ByteArrayUtils.concatAll(V_C, V_S, keyInformation.I_C, keyInformation.I_S,
			SSHString.byteArrayOf(keyInformation.K_S), ByteArrayUtils.toByteArray(keyInformation.prefGroupSize),
			keyInformation.p.toByteArray(), keyInformation.g.toByteArray(), keyInformation.e.toByteArray(),
			keyInformation.f.toByteArray(), keyInformation.K.toByteArrayWithLeadingZeros());
	    } else {
		toHash = ByteArrayUtils.concatAll(V_C, V_S, keyInformation.I_C, keyInformation.I_S,
			SSHString.byteArrayOf(keyInformation.K_S), ByteArrayUtils.toByteArray(keyInformation.minGroupSize),
			ByteArrayUtils.toByteArray(keyInformation.prefGroupSize),
			ByteArrayUtils.toByteArray(keyInformation.maxGroupSize), keyInformation.p.toByteArray(),
			keyInformation.g.toByteArray(), keyInformation.e.toByteArray(), keyInformation.f.toByteArray(),
			keyInformation.K.toByteArrayWithLeadingZeros());
	    }

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

	    byte[] code = { SSHNumbers.SSH_MSG_KEX_DH_GEX_REPLY };

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
