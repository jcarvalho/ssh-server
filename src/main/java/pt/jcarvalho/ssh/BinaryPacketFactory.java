package pt.jcarvalho.ssh;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import pt.jcarvalho.ssh.util.ByteArrayUtils;

public class BinaryPacketFactory {

    private final static Random rand = new SecureRandom();

    public static byte[] packetWithPayload(byte[] payload) {

	byte[] load = ConnectionInfo.get().outgoingCompression.compress(payload, null);

	int length = 5 + load.length;

	int mod = Math.max(ConnectionInfo.get().outgoingCipher.cipherBlockSize(), 8);

	int paddingLength = mod - (length % mod);

	if (paddingLength < 4) {
	    paddingLength += mod;
	}

	length = 1 + load.length + paddingLength;

	byte[] randomPadding = new byte[paddingLength];

	rand.nextBytes(randomPadding);

	byte[] toCipher = ByteArrayUtils.concatAll(ByteArrayUtils.toByteArray(length),
		ByteArrayUtils.toByteArray((byte) paddingLength), load, randomPadding);

	byte[] seqNum = ByteArrayUtils.toByteArray(ConnectionInfo.get().outgoingSeqNumber++);

	byte[] ciphered = ConnectionInfo.get().outgoingCipher.cipher(toCipher);

	byte[] mac = ConnectionInfo.get().outgoingMAC.generateCode(ByteArrayUtils.concat(seqNum, toCipher));

	return ByteArrayUtils.concat(ciphered, mac);
    }

    public static byte[] payloadOfPacket(byte[] firstPacket, byte[] packet, byte[] mac) {

	int mod = Math.max(ConnectionInfo.get().incomingCipher.cipherBlockSize(), 8);

	if (packet.length % mod != 0) {
	    throw new RuntimeException("Packet length was smaller than expected!");
	}

	byte[] deciphered = new byte[packet.length];

	System.arraycopy(firstPacket, 0, deciphered, 0, firstPacket.length);

	// Number of blocks to be deciphered. We do -1 because first was
	// already deciphered
	int nRounds = packet.length / mod - 1;

	byte[] temp = new byte[mod];
	for (int i = 1; i <= nRounds; i++) {
	    System.arraycopy(packet, i * mod, temp, 0, mod);
	    byte[] dec = ConnectionInfo.get().incomingCipher.decipher(temp);
	    System.arraycopy(dec, 0, deciphered, i * mod, mod);
	}

	byte[] seqNum = ByteArrayUtils.toByteArray(ConnectionInfo.get().incomingSeqNumber++);

	byte[] expectedMac = ConnectionInfo.get().incomingMAC.generateCode(ByteArrayUtils.concat(seqNum, deciphered));

	if (!Arrays.equals(mac, expectedMac)) {
	    ConnectionInfo.get().incomingSeqNumber--;
	    throw new RuntimeException("Packet signature invalid!");
	}

	int totalContentLength = packet.length - deciphered[4] - 5;

	byte[] result = new byte[totalContentLength];

	System.arraycopy(deciphered, 5, result, 0, totalContentLength);

	return ConnectionInfo.get().incomingCompression.decompress(result, null);

    }

    /**
     * Setters for the various algorithms
     * 
     */

    public static int getMACSize() {
	return ConnectionInfo.get().incomingMAC.macBytes();
    }

    public static int getMod() {
	return Math.max(ConnectionInfo.get().incomingCipher.cipherBlockSize(), 8);
    }

}
