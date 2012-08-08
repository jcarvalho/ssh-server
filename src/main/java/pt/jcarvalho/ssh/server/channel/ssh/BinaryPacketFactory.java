package pt.jcarvalho.ssh.server.channel.ssh;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import pt.jcarvalho.ssh.common.exception.CipherException;
import pt.jcarvalho.ssh.common.exception.MacException;
import pt.jcarvalho.ssh.common.util.ByteArrayUtils;
import pt.jcarvalho.ssh.server.channel.exception.InvalidPacketException;
import pt.jcarvalho.ssh.server.channel.exception.SecureChannelException;

public class BinaryPacketFactory {

	private final Random rand = new SecureRandom();
	private KeyInformation keyInformation;

	private byte[] readBytes;

	/**
	 * Since both message authentication, compression and encryption must be
	 * done independently for both sides, we must have different classes.
	 */

	public void setKeyInformation(KeyInformation kex) {
		this.keyInformation = kex;
	}

	public byte[] packetWithPayload(byte[] payload)
			throws SecureChannelException {
		try {

			byte[] load = keyInformation.outgoingCompression.compress(payload,
					null);

			int length = 5 + load.length;

			int mod = Math.max(keyInformation.outgoingCipher.cipherBlockSize(),
					8);

			int paddingLength = mod - (length % mod);

			if (paddingLength < 4) {
				paddingLength += mod;
			}

			length = 1 + load.length + paddingLength;

			byte[] randomPadding = new byte[paddingLength];

			rand.nextBytes(randomPadding);

			byte[] toCipher = ByteArrayUtils.concatAll(
					ByteArrayUtils.toByteArray(length),
					ByteArrayUtils.toByteArray((byte) paddingLength), load,
					randomPadding);

			byte[] seqNum = ByteArrayUtils
					.toByteArray(keyInformation.outgoingSeqNumber++);

			byte[] ciphered = keyInformation.outgoingCipher.cipher(toCipher);

			byte[] mac = keyInformation.outgoingMAC.sign(
					keyInformation.outgoingMACKey,
					ByteArrayUtils.concat(seqNum, toCipher));

			return ByteArrayUtils.concat(ciphered, mac);
		} catch (CipherException e) {
			throw new SecureChannelException(e.getMessage());
		} catch (MacException e) {
			throw new SecureChannelException(e.getMessage());
		}
	}

	public byte[] payloadOfPacket(byte[] packet, byte[] mac)
			throws SecureChannelException {
		try {
			int mod = Math.max(keyInformation.incomingCipher.cipherBlockSize(),
					8);

			if (packet.length % mod != 0) {
				throw new InvalidPacketException(
						"Packet length was smaller than expected!");
			}

			byte[] deciphered = new byte[packet.length];

			System.arraycopy(readBytes, 0, deciphered, 0, readBytes.length);

			int nRounds = packet.length / mod - 1;

			byte[] temp = new byte[mod];
			for (int i = 1; i <= nRounds; i++) {
				System.arraycopy(packet, i * mod, temp, 0, mod);
				byte[] dec = keyInformation.incomingCipher.decipher(temp);
				System.arraycopy(dec, 0, deciphered, i * mod, mod);
			}

			byte[] seqNum = ByteArrayUtils
					.toByteArray(keyInformation.incomingSeqNumber++);

			byte[] expectedMac = keyInformation.incomingMAC.sign(
					keyInformation.incomingMACKey,
					ByteArrayUtils.concat(seqNum, deciphered));

			if (!Arrays.equals(mac, expectedMac)) {
				keyInformation.incomingSeqNumber--;
				throw new InvalidPacketException("Packet signature invalid!");
			}

			int totalContentLength = packet.length - deciphered[4] - 5;

			byte[] result = new byte[totalContentLength];

			System.arraycopy(deciphered, 5, result, 0, totalContentLength);

			return keyInformation.incomingCompression.decompress(result, null);

		} catch (CipherException e) {
			throw new SecureChannelException(e.getMessage());
		} catch (MacException e) {
			throw new SecureChannelException(e.getMessage());
		}
	}

	public int numBytesForPacket(byte[] packet) throws SecureChannelException {

		try {

			byte[] deciphered = keyInformation.incomingCipher.decipher(packet);

			readBytes = deciphered;

			return ByteArrayUtils.toInt32(deciphered) + 4;
		} catch (CipherException e) {
			throw new SecureChannelException(e.getMessage());
		}

	}

	/**
	 * Setters for the various algorithms
	 * 
	 */

	public int getMACSize() {
		return keyInformation.incomingMAC.macBytes();
	}

	public int getMod() {
		return Math.max(keyInformation.incomingCipher.cipherBlockSize(), 8);
	}

}
