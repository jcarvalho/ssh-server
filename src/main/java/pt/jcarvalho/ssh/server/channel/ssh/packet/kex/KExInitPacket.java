package pt.jcarvalho.ssh.server.channel.ssh.packet.kex;

import java.security.SecureRandom;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.common.adt.NameList;
import pt.jcarvalho.ssh.common.adt.SSHString;
import pt.jcarvalho.ssh.common.compressor.CompressorNone;
import pt.jcarvalho.ssh.common.encryptor.Encryptor3DES;
import pt.jcarvalho.ssh.common.encryptor.EncryptorAES;
import pt.jcarvalho.ssh.common.kex.DHSHA1;
import pt.jcarvalho.ssh.common.mac.MacMD5;
import pt.jcarvalho.ssh.common.mac.MacMD596;
import pt.jcarvalho.ssh.common.mac.MacSHA1;
import pt.jcarvalho.ssh.common.mac.MacSHA196;
import pt.jcarvalho.ssh.common.util.ByteArrayUtils;
import pt.jcarvalho.ssh.server.channel.ssh.packet.Disconnect;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacket;

public class KExInitPacket extends SSHPacket {

    boolean valid = true;

    byte cookie[] = new byte[16];
    NameList names[];
    boolean firstFollows;
    byte[] raw;

    @Override
    public byte[] binaryRepresentation() {
	return raw;
    }

    @Override
    public String print() {
	StringBuffer buff = new StringBuffer(11);
	buff.append("Cookie: " + ByteArrayUtils.byteArrayToHexString(cookie) + "\n");
	buff.append("kex-algoriths: " + names[0].getNames() + "\n");
	buff.append("server_host_key_algorithms: " + names[1].getNames() + "\n");
	buff.append("encryption_algorithms_client_to_server: " + names[2].getNames() + "\n");
	buff.append("encryption_algorithms_server_to_client: " + names[3].getNames() + "\n");
	buff.append("mac_algorithms_client_to_server: " + names[4].getNames() + "\n");
	buff.append("mac_algorithms_server_to_client: " + names[5].getNames() + "\n");
	buff.append("compression_algorithms_client_to_server: " + names[6].getNames() + "\n");
	buff.append("compression_algorithms_server_to_client: " + names[7].getNames() + "\n");
	buff.append("languages_client_to_server: " + names[8].getNames() + "\n");
	buff.append("languages_server_to_client: " + names[9].getNames() + "\n");
	buff.append("First follows: " + firstFollows);
	return buff.toString();
    }

    public void initWithNameLists(boolean firstFollows, NameList... lists) {
	if (lists.length != 10) {
	    return;
	}
	int totalLength = 0;
	for (NameList list : lists) {
	    totalLength += list.getTotalLength();
	}
	byte[] res = new byte[totalLength + 22];
	res[0] = SSHNumbers.SSH_MSG_KEXINIT;
	SecureRandom rand = new SecureRandom();
	byte[] cookie = new byte[16];
	rand.nextBytes(cookie);
	System.arraycopy(cookie, 0, res, 1, 16);
	int offset = 17;
	for (NameList list : lists) {
	    System.arraycopy(list.toByteArray(), 0, res, offset, list.getTotalLength());
	    offset += list.getTotalLength();
	}
	this.raw = res;
	keyInformation.I_S = SSHString.byteArrayOf(res);
    }

    @Override
    public void initWithData(byte[] data) {
	this.raw = data;
	System.arraycopy(data, 1, cookie, 0, 16);

	names = NameList.extractNameLists(data, 17, 10);

	if (data[data.length - 5] == 0) {
	    firstFollows = false;
	} else {
	    firstFollows = true;
	}
	keyInformation.I_C = SSHString.byteArrayOf(data);
    }

    /**
     * With both algorithm preferences, setup the 'temporary' algorithms that
     * will be put to use after key exchange is complete
     */

    @Override
    public void process() {

	// Key Information Algorithm

	// More Key Exchange Methods would go here

	for (String prefKex : names[0].getNames()) {
	    System.out.println("Analizing: " + prefKex);
	    if (prefKex.contains("group-exchange")) {
		break;
	    } else if (prefKex.equals("diffie-hellman-group1-sha1")) {
		keyInformation.groupExchangeMode = false;
		keyInformation.group = 1;
		break;
	    } else if (prefKex.equals("diffie-hellman-group14-sha1")) {
		keyInformation.groupExchangeMode = false;
		keyInformation.group = 14;
		break;
	    }
	}

	keyInformation.kex = new DHSHA1();

	// Incoming Cipher Algorithm

	for (String prefIncEnc : names[2].getNames()) {
	    if (prefIncEnc.startsWith("aes") && prefIncEnc.endsWith("-cbc")) {
		int size = Integer.parseInt(prefIncEnc.substring(3, 6));
		keyInformation.TincomingCipher = EncryptorAES.cipherWithSize(size);
		break;
	    } else if (prefIncEnc.equals("3des-cbc")) {
		keyInformation.TincomingCipher = new Encryptor3DES();
		break;
	    }
	}

	// Outgoing Cipher Algorithm

	for (String prefOutEnc : names[3].getNames()) {
	    if (prefOutEnc.startsWith("aes") && prefOutEnc.endsWith("-cbc")) {
		int size = Integer.parseInt(prefOutEnc.substring(3, 6));
		keyInformation.ToutgoingCipher = EncryptorAES.cipherWithSize(size);
		break;
	    } else if (prefOutEnc.equals("3des-cbc")) {
		keyInformation.ToutgoingCipher = new Encryptor3DES();
		break;
	    }
	}

	// Incoming MAC algorithm

	for (String prefIncMAC : names[4].getNames()) {
	    if (prefIncMAC.equals("hmac-sha1")) {
		keyInformation.TincomingMAC = new MacSHA1();
		break;
	    } else if (prefIncMAC.equals("hmac-sha1-96")) {
		keyInformation.TincomingMAC = new MacSHA196();
		break;
	    } else if (prefIncMAC.equals("hmac-md5")) {
		keyInformation.TincomingMAC = new MacMD5();
		break;
	    } else if (prefIncMAC.equals("hmac-md5-96")) {
		keyInformation.TincomingMAC = new MacMD596();
		break;
	    }
	}

	// Outgoing MAC algorithm

	for (String prefOutMAC : names[5].getNames()) {
	    if (prefOutMAC.equals("hmac-sha1")) {
		keyInformation.ToutgoingMAC = new MacSHA1();
		break;
	    } else if (prefOutMAC.equals("hmac-sha1-96")) {
		keyInformation.ToutgoingMAC = new MacSHA196();
		break;
	    } else if (prefOutMAC.equals("hmac-md5")) {
		keyInformation.ToutgoingMAC = new MacMD5();
		break;
	    } else if (prefOutMAC.equals("hmac-md5-96")) {
		keyInformation.ToutgoingMAC = new MacMD596();
		break;
	    }
	}

	// No compression algorithm is currently supported, so no point in
	// checking
	keyInformation.TincomingCompression = new CompressorNone();
	keyInformation.ToutgoingCompression = new CompressorNone();

	if (keyInformation.kex == null || keyInformation.TincomingCipher == null || keyInformation.ToutgoingCipher == null
		|| keyInformation.TincomingMAC == null || keyInformation.ToutgoingMAC == null) {
	    valid = false;
	}

    }

    @Override
    public SSHPacket nextPacket() {
	return (valid ? null : new Disconnect("Unsupported algorithm!", SSHNumbers.SSH_DISCONNECT_KEY_EXCHANGE_FAILED));
    }

}
