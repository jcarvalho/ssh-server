package pt.jcarvalho.ssh.server.channel.ssh;

import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.DHParameterSpec;

import pt.jcarvalho.ssh.common.adt.MPInt;
import pt.jcarvalho.ssh.common.cipher.AbstractCipher;
import pt.jcarvalho.ssh.common.cipher.CipherNone;
import pt.jcarvalho.ssh.common.compression.AbstractCompression;
import pt.jcarvalho.ssh.common.compression.CompressionNone;
import pt.jcarvalho.ssh.common.kex.AbstractKeyExchange;
import pt.jcarvalho.ssh.common.mac.AbstractMAC;
import pt.jcarvalho.ssh.common.mac.MACNone;

public class KeyInformation {

	public boolean compatMode = false, groupExchangeMode = true;

	public int channel = 0, group = 1;
	private int nextChannel = 0;
	public Map<Integer, ConnectionState> outgoingChannels = new HashMap<Integer, ConnectionState>(),
			incomingChannels = new HashMap<Integer, ConnectionState>();

	public String command;

	public String username, serviceName;

	public int incomingSeqNumber;
	public int outgoingSeqNumber;

	public byte[] incomingMACKey;
	public byte[] outgoingMACKey;
	public byte[] incomingCipherKey;
	public byte[] outgoingCipherKey;

	public AbstractCipher incomingCipher = new CipherNone(),
			outgoingCipher = new CipherNone();
	public AbstractMAC incomingMAC = new MACNone(),
			outgoingMAC = new MACNone();
	public AbstractCompression incomingCompression = new CompressionNone(),
			outgoingCompression = new CompressionNone();

	public AbstractCipher TincomingCipher, ToutgoingCipher;
	public AbstractMAC TincomingMAC, ToutgoingMAC;
	public AbstractCompression TincomingCompression, ToutgoingCompression;

	public int minGroupSize;
	public int prefGroupSize;
	public int maxGroupSize;

	public String serverString = "SSH-2.0-SIRSssh_0.1";
	public String clientString;

	public MPInt p, g, e, f, K;

	public byte[] I_C, I_S, K_S, H, sessionId;

	public AbstractKeyExchange kex;

	public DHParameterSpec dhParameterSpec;
	public boolean x11;

	public KeyInformation() {
	}

	public void commitAlgorithms() {
		incomingCipher = TincomingCipher;
		outgoingCipher = ToutgoingCipher;

		incomingMAC = TincomingMAC;
		outgoingMAC = ToutgoingMAC;

		incomingCompression = TincomingCompression;
		outgoingCompression = ToutgoingCompression;
	}

	public int openNewChannel() {

		outgoingChannels.put(nextChannel, ConnectionState.OPEN);

		return nextChannel++;

	}

}
