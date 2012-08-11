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

    private byte[] incomingMACKey;
    private byte[] outgoingMACKey;
    private byte[] incomingCipherKey;
    private byte[] outgoingCipherKey;

    // Currently in use

    private Encryptor incomingCipher = new EncryptorNone();
    private Encryptor outgoingCipher = new EncryptorNone();

    private MAC incomingMAC = new MACNone();
    private MAC outgoingMAC = new MACNone();

    private Compressor incomingCompression = new CompressorNone();
    private Compressor outgoingCompression = new CompressorNone();

    // Agreed upon, but not yet in use

    private Encryptor TincomingCipher;
    private Encryptor ToutgoingCipher;

    private MAC TincomingMAC;
    private MAC ToutgoingMAC;

    private Compressor TincomingCompression;
    private Compressor ToutgoingCompression;

    public int minGroupSize;
    public int prefGroupSize;
    public int maxGroupSize;

    public String serverString = "SSH-2.0-SIRSssh_0.1";
    public String clientString;

    public MPInt p, g, e, f, K;

    public byte[] I_C, I_S, K_S, H, sessionId;

    public KeyExchange kex;

    public DHParameterSpec dhParameterSpec;

    private ConnectionInfo() {

    }

    public void commitAlgorithms() {
	setIncomingCipher(getTincomingCipher());
	setOutgoingCipher(getToutgoingCipher());

	setIncomingMAC(getTincomingMAC());
	setOutgoingMAC(getToutgoingMAC());

	setIncomingCompression(getTincomingCompression());
	setOutgoingCompression(getToutgoingCompression());
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

    // Getters and setters...

    public Encryptor getIncomingCipher() {
	return incomingCipher;
    }

    public void setIncomingCipher(Encryptor incomingCipher) {
	this.incomingCipher = incomingCipher;
    }

    public Encryptor getOutgoingCipher() {
	return outgoingCipher;
    }

    public void setOutgoingCipher(Encryptor outgoingCipher) {
	this.outgoingCipher = outgoingCipher;
    }

    public byte[] getOutgoingMACKey() {
	return outgoingMACKey;
    }

    public void setOutgoingMACKey(byte[] outgoingMACKey) {
	this.outgoingMACKey = outgoingMACKey;
    }

    public byte[] getIncomingMACKey() {
	return incomingMACKey;
    }

    public void setIncomingMACKey(byte[] incomingMACKey) {
	this.incomingMACKey = incomingMACKey;
    }

    public byte[] getIncomingCipherKey() {
	return incomingCipherKey;
    }

    public void setIncomingCipherKey(byte[] incomingCipherKey) {
	this.incomingCipherKey = incomingCipherKey;
    }

    public byte[] getOutgoingCipherKey() {
	return outgoingCipherKey;
    }

    public void setOutgoingCipherKey(byte[] outgoingCipherKey) {
	this.outgoingCipherKey = outgoingCipherKey;
    }

    public MAC getIncomingMAC() {
	return incomingMAC;
    }

    public void setIncomingMAC(MAC incomingMAC) {
	this.incomingMAC = incomingMAC;
    }

    public MAC getOutgoingMAC() {
	return outgoingMAC;
    }

    public void setOutgoingMAC(MAC outgoingMAC) {
	this.outgoingMAC = outgoingMAC;
    }

    public Compressor getIncomingCompression() {
	return incomingCompression;
    }

    public void setIncomingCompression(Compressor incomingCompression) {
	this.incomingCompression = incomingCompression;
    }

    public Compressor getOutgoingCompression() {
	return outgoingCompression;
    }

    public void setOutgoingCompression(Compressor outgoingCompression) {
	this.outgoingCompression = outgoingCompression;
    }

    public Encryptor getTincomingCipher() {
	return TincomingCipher;
    }

    public void setTincomingCipher(Encryptor tincomingCipher) {
	TincomingCipher = tincomingCipher;
    }

    public Encryptor getToutgoingCipher() {
	return ToutgoingCipher;
    }

    public void setToutgoingCipher(Encryptor toutgoingCipher) {
	ToutgoingCipher = toutgoingCipher;
    }

    public MAC getTincomingMAC() {
	return TincomingMAC;
    }

    public void setTincomingMAC(MAC tincomingMAC) {
	TincomingMAC = tincomingMAC;
    }

    public MAC getToutgoingMAC() {
	return ToutgoingMAC;
    }

    public void setToutgoingMAC(MAC toutgoingMAC) {
	ToutgoingMAC = toutgoingMAC;
    }

    public Compressor getTincomingCompression() {
	return TincomingCompression;
    }

    public void setTincomingCompression(Compressor tincomingCompression) {
	TincomingCompression = tincomingCompression;
    }

    public Compressor getToutgoingCompression() {
	return ToutgoingCompression;
    }

    public void setToutgoingCompression(Compressor toutgoingCompression) {
	ToutgoingCompression = toutgoingCompression;
    }

}
