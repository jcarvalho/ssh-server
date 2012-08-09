package pt.jcarvalho.ssh.packet.channel;

import pt.jcarvalho.ssh.ConnectionInfo;
import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.adt.SSHString;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ClientGenerated;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

@ClientGenerated
public class ChannelOpen extends AbstractPacket {

    private String type;

    private int channel, initialWindow, maxPacketSize;

    private SSHPacket next;

    int maxPack;

    private String address;

    int port;

    @Override
    public byte[] binaryRepresentation() {
	return null;
    }

    @Override
    public void initWithData(byte[] data) {

	type = new String(SSHString.extractString(data, 1));

	if (type.equalsIgnoreCase("session")) {

	    int offset = 5 + type.length();

	    channel = ByteArrayUtils.toInt32(data, offset);

	    ConnectionInfo.get().channel = channel;

	    initialWindow = ByteArrayUtils.toInt32(data, offset + 4);

	    maxPacketSize = ByteArrayUtils.toInt32(data, offset + 8);
	} else if (type.equalsIgnoreCase("x11")) {
	    int offset = 5 + type.length();

	    channel = ByteArrayUtils.toInt32(data, offset);
	    initialWindow = ByteArrayUtils.toInt32(data, offset + 4);
	    maxPack = ByteArrayUtils.toInt32(data, offset + 8);
	    address = new String(SSHString.extractString(data, offset + 12));
	    offset += 12 + 1 + address.length();
	    port = ByteArrayUtils.toInt32(data, offset);
	}

    }

    @Override
    public void process() {
	if (!type.equals("session")) {
	    next = new ChannelOpenFailure(channel, SSHNumbers.SSH_OPEN_UNKNOWN_CHANNEL_TYPE, "Unknown channel");
	}

	ConnectionInfo.get().incomingChannels.add(channel);

	next = new ChannelOpenConf(channel, ConnectionInfo.get().openNewChannel(), initialWindow, maxPacketSize);

    }

    @Override
    public SSHPacket nextPacket() {
	return next;
    }

    @Override
    public String print() {
	return "Channel open. Type: " + type + ". ID: " + channel;
    }
}
