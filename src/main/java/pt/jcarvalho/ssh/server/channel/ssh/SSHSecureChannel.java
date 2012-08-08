package pt.jcarvalho.ssh.server.channel.ssh;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;

import pt.jcarvalho.ssh.common.adt.NameList;
import pt.jcarvalho.ssh.common.util.ByteArrayUtils;
import pt.jcarvalho.ssh.server.channel.SecureChannel;
import pt.jcarvalho.ssh.server.channel.exception.ChannelIOException;
import pt.jcarvalho.ssh.server.channel.exception.SecureChannelException;
import pt.jcarvalho.ssh.server.channel.exception.UnsupportedProtocolException;
import pt.jcarvalho.ssh.server.channel.ssh.packet.Disconnect;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacketFactory;
import pt.jcarvalho.ssh.server.channel.ssh.packet.channel.ChannelClose;
import pt.jcarvalho.ssh.server.channel.ssh.packet.channel.ChannelData;
import pt.jcarvalho.ssh.server.channel.ssh.packet.channel.ChannelRequest;
import pt.jcarvalho.ssh.server.channel.ssh.packet.kex.DHGexReply;
import pt.jcarvalho.ssh.server.channel.ssh.packet.kex.DHKexReply;
import pt.jcarvalho.ssh.server.channel.ssh.packet.kex.KExInitPacket;
import pt.jcarvalho.ssh.server.channel.ssh.packet.kex.NewKeys;

public class SSHSecureChannel implements SecureChannel {

    private final Socket socket;
    private final OutputStream output;
    private final InputStream input;

    BinaryPacketFactory binaryPacket = new BinaryPacketFactory();
    KeyInformation keyInformation = new KeyInformation();
    ChannelState state = ChannelState.SETTINGUP;

    public SSHSecureChannel(Socket socket) {
	this.socket = socket;
	try {
	    this.output = socket.getOutputStream();
	    this.input = socket.getInputStream();
	} catch (IOException e) {
	    try {
		socket.close();
	    } catch (IOException ex) {
		// Well, at least we tried...
	    }
	    throw new RuntimeException("Error while initializing SSHSecureChannel, cannot get streams from socket!");
	}
	binaryPacket.setKeyInformation(keyInformation);
    }

    @Override
    public String setup() throws IOException {

	byte[] protoVersionExc = new String(keyInformation.serverString + "\r\n").getBytes();

	output.write(protoVersionExc);

	byte[] id = new byte[255];

	int i;

	for (i = 0; i < 255; i++) {
	    byte[] one = new byte[1];
	    input.read(one);
	    if (one[0] == '\r') {
		byte[] another = new byte[1];
		input.read(another);
		if (another[0] == '\n') {
		    break;
		}
		id[i++] = one[0];
		id[i] = another[0];

	    }
	    id[i] = one[0];
	}

	byte[] idStr = new byte[i];

	System.arraycopy(id, 0, idStr, 0, i);

	String clientVersion = new String(idStr);
	keyInformation.clientString = clientVersion;
	String clientData[] = clientVersion.split("-");
	if (Float.parseFloat(clientData[1]) < 2.0) {
	    throw new UnsupportedProtocolException(clientData[1]);
	}

	// Start sending packets

	KExInitPacket packet = new KExInitPacket();
	packet.setKeyInformation(keyInformation);
	if (System.getProperty("os.name").startsWith("Win")) {
	    packet.initWithNameLists(
	    // first-follows
		    false,
		    // kex-algorithms
		    new NameList("diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1"),
		    // server_host_key_algorithms
		    new NameList("ssh-rsa"),
		    // encryption_algorithms_client_to_server
		    new NameList("aes128-cbc"),
		    // encryption_algorithms_server_to_client
		    new NameList("aes128-cbc"),
		    // mac_algorithms_client_to_server
		    new NameList("hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96"),
		    // mac_algorithms_server_to_client
		    new NameList("hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96"),
		    // compression_algorithms_client_to_server
		    new NameList("none"),
		    // compression_algorithms_server_to_client
		    new NameList("none"),
		    // languages_client_to_server
		    new NameList(""),
		    // languages_server_to_client
		    new NameList(""));
	} else {
	    packet.initWithNameLists(
	    // first-follows
		    false,
		    // kex-algorithms
		    new NameList("diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1"),
		    // server_host_key_algorithms
		    new NameList("ssh-rsa"),
		    // encryption_algorithms_client_to_server
		    new NameList("aes256-cbc,aes192-cbc,3des-cbc,aes128-cbc"),
		    // encryption_algorithms_server_to_client
		    new NameList("aes256-cbc,aes192-cbc,3des-cbc,aes128-cbc"),
		    // mac_algorithms_client_to_server
		    new NameList("hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96"),
		    // mac_algorithms_server_to_client
		    new NameList("hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96"),
		    // compression_algorithms_client_to_server
		    new NameList("none"),
		    // compression_algorithms_server_to_client
		    new NameList("none"),
		    // languages_client_to_server
		    new NameList(""),
		    // languages_server_to_client
		    new NameList(""));
	}

	output.write(binaryPacket.packetWithPayload(packet.binaryRepresentation()));

	while (true) {
	    byte[] first = new byte[binaryPacket.getMod()];

	    if (input.read(first) == -1) {
		System.out.println("Socket closed!");
		throw new SecureChannelException("SSH Secure Channel Setup failed!");
	    }

	    int numBytesForPacket = binaryPacket.numBytesForPacket(first);

	    byte[] buffer = new byte[numBytesForPacket];

	    System.arraycopy(first, 0, buffer, 0, first.length);

	    if (first.length != numBytesForPacket) {
		input.read(buffer, first.length, numBytesForPacket - first.length);
	    }

	    byte[] mac = new byte[binaryPacket.getMACSize()];

	    if (mac.length > 0) {
		input.read(mac);
	    }

	    byte[] reconstructed = binaryPacket.payloadOfPacket(buffer, mac);

	    SSHPacket pack = SSHPacketFactory.processPacket(reconstructed, keyInformation);

	    System.out.println("Read: " + pack.print());

	    pack.process();

	    SSHPacket response = pack.nextPacket();

	    if (response != null) {
		response.setKeyInformation(keyInformation);
		byte[] respBytes = response.binaryRepresentation();
		if (respBytes != null) {
		    byte[] responseRepr = binaryPacket.packetWithPayload(respBytes);
		    output.write(responseRepr);
		    // FIXME Terrible hack!
		    if (response instanceof DHGexReply || response instanceof DHKexReply) {
			byte[] repr = new NewKeys().binaryRepresentation();
			output.write(binaryPacket.packetWithPayload(repr));
		    }
		}
		if (response.isLast()) {
		    if (response instanceof Disconnect)
			state = ChannelState.CLOSED;
		    break;
		}
	    }

	    if (pack.isLast()) {
		if (response instanceof Disconnect)
		    state = ChannelState.CLOSED;
		break;
	    }

	}

	if (state == ChannelState.SETTINGUP)
	    state = ChannelState.EXECUTING;
	return keyInformation.command;

    }

    @Override
    public String readLine() throws IOException {
	if (state != ChannelState.EXECUTING)
	    throw new ChannelIOException("ERROR: Trying to read a line from a closed connection!");

	StringBuffer sb = new StringBuffer();

	boolean last = false;

	while (true) {
	    byte[] first = new byte[binaryPacket.getMod()];

	    if (input.read(first) == -1) {
		System.out.println("Socket closed!");
		break;
	    }

	    int numBytesForPacket = binaryPacket.numBytesForPacket(first);

	    byte[] buffer = new byte[numBytesForPacket];

	    System.arraycopy(first, 0, buffer, 0, first.length);

	    if (first.length != numBytesForPacket) {
		input.read(buffer, first.length, numBytesForPacket - first.length);
	    }

	    byte[] mac = new byte[binaryPacket.getMACSize()];

	    if (mac.length > 0) {
		input.read(mac);
	    }

	    byte[] reconstructed = binaryPacket.payloadOfPacket(buffer, mac);

	    SSHPacket pack = SSHPacketFactory.processPacket(reconstructed, keyInformation);

	    System.out.println("Read: " + pack.print());

	    pack.process();

	    if (pack instanceof ChannelData) {
		ChannelData d = (ChannelData) pack;
		if (d.str.endsWith("\n")) {
		    last = true;
		    sb.append(d.str);
		} else if (d.str.endsWith("\r")) {
		    last = true;
		    sb.append(d.str);
		    ((ChannelData) pack).append((byte) '\n');
		} else {
		    sb.append(d.str);
		}
	    }

	    byte[] respBytes = pack.binaryRepresentation();
	    if (respBytes != null) {
		byte[] responseRepr = binaryPacket.packetWithPayload(respBytes);
		output.write(responseRepr);
	    }

	    if (last)
		break;

	}

	String finalStr = stripBackspaces(sb.toString());

	return finalStr.substring(0, finalStr.length() - 1);
    }

    private String stripBackspaces(String s) {
	byte[] data = null;
	try {
	    data = s.getBytes("UTF-8");
	} catch (UnsupportedEncodingException e) {
	    e.printStackTrace();
	}

	byte[] newData = new byte[data.length];

	int i, writeIndex;

	for (i = 0, writeIndex = 0; i < data.length; i++) {
	    if (data[i] == (byte) 0x8) {
		if (writeIndex > 0) {
		    writeIndex--;
		}
	    } else {
		newData[writeIndex++] = data[i];
	    }

	}

	try {
	    return new String(newData, 0, writeIndex, "UTF-8");
	} catch (UnsupportedEncodingException e) {
	    e.printStackTrace();
	    return null;
	}

    }

    @Override
    public void write(String string) throws IOException {
	if (state != ChannelState.EXECUTING)
	    throw new ChannelIOException("ERROR: Trying to write a line from to closed connection!");

	String str = string + (string.length() == 0 ? "" : "\r\n") + "> ";

	ChannelData packet = new ChannelData(keyInformation.channel, str.getBytes("UTF-8"));

	output.write(binaryPacket.packetWithPayload(packet.binaryRepresentation()));
    }

    @Override
    public void close(int code) throws IOException {

	if (state != ChannelState.EXECUTING) {
	    socket.close();
	    return;
	}

	ChannelRequest packet = new ChannelRequest(keyInformation.channel, "exit-status", false, ByteArrayUtils.toByteArray(code));

	output.write(binaryPacket.packetWithPayload(packet.binaryRepresentation()));

	ChannelClose pack = new ChannelClose(keyInformation.channel);
	output.write(binaryPacket.packetWithPayload(pack.binaryRepresentation()));

	socket.close();
    }

    @Override
    public void close() throws IOException {
	this.close(1);
    }

}
