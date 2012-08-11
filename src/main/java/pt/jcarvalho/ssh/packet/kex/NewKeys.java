package pt.jcarvalho.ssh.packet.kex;

import pt.jcarvalho.ssh.ConnectionInfo;
import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.Encryptor.CipherException;
import pt.jcarvalho.ssh.MAC.MacException;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.base.Disconnect;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

public class NewKeys extends AbstractPacket {

    private final ConnectionInfo keyInformation = ConnectionInfo.get();

    boolean ok = true;

    @Override
    public byte[] binaryRepresentation() {
	byte[] res = { SSHNumbers.SSH_MSG_NEWKEYS };
	return res;
    }

    @Override
    public void initWithData(byte[] data) {
    }

    private byte[] hashWithCharacterAndLength(char character, int size) {
	int actualSize = keyInformation.kex.hashSize();
	byte[] ch = new byte[1];
	ch[0] = (byte) character;
	byte[] first = ByteArrayUtils.concatAll(keyInformation.K.toByteArrayWithLeadingZeros(), keyInformation.H, ch,
		keyInformation.sessionId);
	byte[] hashed = keyInformation.kex.hashOf(first);
	if (size == -1 || actualSize == size) {
	    return hashed;
	}
	if (size < actualSize) {
	    byte[] newBytes = new byte[size];
	    System.arraycopy(hashed, 0, newBytes, 0, size);
	    return newBytes;
	} else {

	    byte[] retArray = hashed;

	    int numSteps = size / actualSize;
	    if (size % actualSize != 0)
		numSteps++;

	    for (int i = 1; i < numSteps; i++) {
		byte[] th = ByteArrayUtils.concatAll(keyInformation.K.toByteArrayWithLeadingZeros(), keyInformation.H, retArray);
		retArray = ByteArrayUtils.concat(retArray, keyInformation.kex.hashOf(th));
	    }

	    byte[] newBytes = new byte[size];
	    System.arraycopy(retArray, 0, newBytes, 0, size);

	    return newBytes;
	}
    }

    @Override
    public void process() {

	try {

	    keyInformation.commitAlgorithms();

	    keyInformation.getIncomingCipher().setIV(hashWithCharacterAndLength('A', keyInformation.getIncomingCipher().cipherBlockSize()));

	    keyInformation.getOutgoingCipher().setIV(hashWithCharacterAndLength('B', keyInformation.getOutgoingCipher().cipherBlockSize()));

	    keyInformation.setIncomingCipherKey(hashWithCharacterAndLength('C', keyInformation.getIncomingCipher().keySize()));

	    keyInformation.getIncomingCipher().setKey(keyInformation.getIncomingCipherKey());

	    keyInformation.setOutgoingCipherKey(hashWithCharacterAndLength('D', keyInformation.getOutgoingCipher().keySize()));

	    keyInformation.getOutgoingCipher().setKey(keyInformation.getOutgoingCipherKey());

	    keyInformation.getIncomingMAC().setKey(hashWithCharacterAndLength('E', keyInformation.getIncomingMAC().macBytes()));

	    keyInformation.getOutgoingMAC().setKey(hashWithCharacterAndLength('F', keyInformation.getOutgoingMAC().macBytes()));

	} catch (CipherException | MacException e) {
	    e.printStackTrace();
	}

    }

    @Override
    public SSHPacket nextPacket() {
	return (ok ? null : new Disconnect("An error ocurred while calculating the session keys!",
		SSHNumbers.SSH_DISCONNECT_KEY_EXCHANGE_FAILED));
    }

}
