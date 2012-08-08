package pt.jcarvalho.ssh.server.channel.ssh.packet.kex;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.common.exception.CipherException;
import pt.jcarvalho.ssh.common.exception.HashException;
import pt.jcarvalho.ssh.common.util.ByteArrayUtils;
import pt.jcarvalho.ssh.server.channel.ssh.packet.Disconnect;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacket;

public class NewKeys extends SSHPacket {

	boolean ok = true;

	@Override
	public byte[] binaryRepresentation() {
		byte[] res = { SSHNumbers.SSH_MSG_NEWKEYS };
		return res;
	}

	@Override
	public void initWithData(byte[] data) {
	}

	private byte[] hashWithCharacterAndLength(char character, int size)
			throws HashException {
		int actualSize = keyInformation.kex.hashSize();
		byte[] ch = new byte[1];
		ch[0] = (byte) character;
		byte[] first = ByteArrayUtils.concatAll(
				keyInformation.K.toByteArrayWithLeadingZeros(),
				keyInformation.H, ch, keyInformation.sessionId);
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
				byte[] th = ByteArrayUtils.concatAll(
						keyInformation.K.toByteArrayWithLeadingZeros(),
						keyInformation.H, retArray);
				retArray = ByteArrayUtils.concat(retArray,
						keyInformation.kex.hashOf(th));
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

			keyInformation.incomingCipher.setIV(hashWithCharacterAndLength('A',
					keyInformation.incomingCipher.cipherBlockSize()));

			keyInformation.outgoingCipher.setIV(hashWithCharacterAndLength('B',
					keyInformation.outgoingCipher.cipherBlockSize()));

			keyInformation.incomingCipherKey = hashWithCharacterAndLength('C',
					keyInformation.incomingCipher.keySize());

			keyInformation.incomingCipher
					.setKey(keyInformation.incomingCipherKey);

			keyInformation.outgoingCipherKey = hashWithCharacterAndLength('D',
					keyInformation.outgoingCipher.keySize());

			keyInformation.outgoingCipher
					.setKey(keyInformation.outgoingCipherKey);

			keyInformation.incomingMACKey = hashWithCharacterAndLength('E',
					keyInformation.incomingMAC.macBytes());

			keyInformation.outgoingMACKey = hashWithCharacterAndLength('F',
					keyInformation.outgoingMAC.macBytes());

		} catch (HashException e) {
			e.printStackTrace();
		} catch (CipherException e) {
			e.printStackTrace();
		}

	}

	@Override
	public SSHPacket nextPacket() {
		return (ok ? null : new Disconnect(
				"An error ocurred while calculating the session keys!",
				SSHNumbers.SSH_DISCONNECT_KEY_EXCHANGE_FAILED));
	}

}
