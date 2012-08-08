package pt.jcarvalho.ssh.server.channel.ssh;

import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.DHParameterSpec;

import pt.jcarvalho.ssh.common.Compressor;
import pt.jcarvalho.ssh.common.Encryptor;
import pt.jcarvalho.ssh.common.adt.MPInt;
import pt.jcarvalho.ssh.common.compressor.CompressorNone;
import pt.jcarvalho.ssh.common.encryptor.EncryptorNone;
import pt.jcarvalho.ssh.common.kex.KeyExchange;
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

    public Encryptor incomingCipher = new EncryptorNone(), outgoingCipher = new EncryptorNone();
    public AbstractMAC incomingMAC = new MACNone(), outgoingMAC = new MACNone();
    public Compressor incomingCompression = new CompressorNone(), outgoingCompression = new CompressorNone();

    public Encryptor TincomingCipher, ToutgoingCipher;
    public AbstractMAC TincomingMAC, ToutgoingMAC;
    public Compressor TincomingCompression, ToutgoingCompression;

    public int minGroupSize;
    public int prefGroupSize;
    public int maxGroupSize;

    public String serverString = "SSH-2.0-SIRSssh_0.1";
    public String clientString;

    public MPInt p, g, e, f, K;

    public byte[] I_C, I_S, K_S, H, sessionId;

    public KeyExchange kex;

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
