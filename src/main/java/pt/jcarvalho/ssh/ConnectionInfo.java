package pt.jcarvalho.ssh;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.spec.DHParameterSpec;

import pt.jcarvalho.ssh.adt.MPInt;
import pt.jcarvalho.ssh.compressor.CompressorNone;
import pt.jcarvalho.ssh.encryptor.EncryptorNone;
import pt.jcarvalho.ssh.mac.MACNone;

public class ConnectionInfo {

    public boolean compatMode = false, groupExchangeMode = true;

    public int channel = 0, group = 1;
    private int nextChannel = 0;
    public List<Integer> outgoingChannels = new ArrayList<>(), incomingChannels = new ArrayList<>();

    public String command;

    public String username, serviceName;

    public int incomingSeqNumber;
    public int outgoingSeqNumber;

    public byte[] incomingMACKey;
    public byte[] outgoingMACKey;
    public byte[] incomingCipherKey;
    public byte[] outgoingCipherKey;

    // Currently in use

    public Encryptor incomingCipher = new EncryptorNone(), outgoingCipher = new EncryptorNone();
    public MAC incomingMAC = new MACNone(), outgoingMAC = new MACNone();
    public Compressor incomingCompression = new CompressorNone(), outgoingCompression = new CompressorNone();

    // Agreed upon, but not yet in use

    public Encryptor TincomingCipher, ToutgoingCipher;
    public MAC TincomingMAC, ToutgoingMAC;
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

    private ConnectionInfo() {

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

	outgoingChannels.add(nextChannel);

	return nextChannel++;

    }

    // Actually getting the instance

    private final static ThreadLocal<ConnectionInfo> informations = new ThreadLocal<ConnectionInfo>();

    public static ConnectionInfo get() {
	ConnectionInfo information = informations.get();
	if (information == null) {
	    information = new ConnectionInfo();
	    informations.set(information);
	}
	return information;
    }

    public static void clearInformationForThread() {
	informations.set(null);
    }

}
