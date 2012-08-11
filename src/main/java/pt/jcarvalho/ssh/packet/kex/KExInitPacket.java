package pt.jcarvalho.ssh.packet.kex;

import java.security.SecureRandom;

import pt.jcarvalho.ssh.ConnectionInfo;
import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.adt.NameList;
import pt.jcarvalho.ssh.adt.SSHString;
import pt.jcarvalho.ssh.compressor.CompressorNone;
import pt.jcarvalho.ssh.encryptor.Encryptor3DES;
import pt.jcarvalho.ssh.encryptor.EncryptorAES;
import pt.jcarvalho.ssh.kex.DHSHA1;
import pt.jcarvalho.ssh.mac.MacMD5;
import pt.jcarvalho.ssh.mac.MacMD596;
import pt.jcarvalho.ssh.mac.MacSHA1;
import pt.jcarvalho.ssh.mac.MacSHA196;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.base.Disconnect;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

public class KExInitPacket extends AbstractPacket {

    private final ConnectionInfo keyInformation = ConnectionInfo.get();

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
		keyInformation.setTincomingCipher(EncryptorAES.cipherWithSize(size));
		break;
	    } else if (prefIncEnc.equals("3des-cbc")) {
		keyInformation.setTincomingCipher(new Encryptor3DES());
		break;
	    }
	}

	// Outgoing Cipher Algorithm

	for (String prefOutEnc : names[3].getNames()) {
	    if (prefOutEnc.startsWith("aes") && prefOutEnc.endsWith("-cbc")) {
		int size = Integer.parseInt(prefOutEnc.substring(3, 6));
		keyInformation.setToutgoingCipher(EncryptorAES.cipherWithSize(size));
		break;
	    } else if (prefOutEnc.equals("3des-cbc")) {
		keyInformation.setToutgoingCipher(new Encryptor3DES());
		break;
	    }
	}

	// Incoming MAC algorithm

	for (String prefIncMAC : names[4].getNames()) {
	    if (prefIncMAC.equals("hmac-sha1")) {
		keyInformation.setTincomingMAC(new MacSHA1());
		break;
	    } else if (prefIncMAC.equals("hmac-sha1-96")) {
		keyInformation.setTincomingMAC(new MacSHA196());
		break;
	    } else if (prefIncMAC.equals("hmac-md5")) {
		keyInformation.setTincomingMAC(new MacMD5());
		break;
	    } else if (prefIncMAC.equals("hmac-md5-96")) {
		keyInformation.setTincomingMAC(new MacMD596());
		break;
	    }
	}

	// Outgoing MAC algorithm

	for (String prefOutMAC : names[5].getNames()) {
	    if (prefOutMAC.equals("hmac-sha1")) {
		keyInformation.setToutgoingMAC(new MacSHA1());
		break;
	    } else if (prefOutMAC.equals("hmac-sha1-96")) {
		keyInformation.setToutgoingMAC(new MacSHA196());
		break;
	    } else if (prefOutMAC.equals("hmac-md5")) {
		keyInformation.setToutgoingMAC(new MacMD5());
		break;
	    } else if (prefOutMAC.equals("hmac-md5-96")) {
		keyInformation.setToutgoingMAC(new MacMD596());
		break;
	    }
	}

	// No compression algorithm is currently supported, so no point in
	// checking
	keyInformation.setTincomingCompression(new CompressorNone());
	keyInformation.setToutgoingCompression(new CompressorNone());

	if (keyInformation.kex == null || keyInformation.getTincomingCipher() == null || keyInformation.getToutgoingCipher() == null
		|| keyInformation.getTincomingMAC() == null || keyInformation.getToutgoingMAC() == null) {
	    valid = false;
	}

    }

    @Override
    public SSHPacket nextPacket() {
	return (valid ? null : new Disconnect("Unsupported algorithm!", SSHNumbers.SSH_DISCONNECT_KEY_EXCHANGE_FAILED));
    }

}
