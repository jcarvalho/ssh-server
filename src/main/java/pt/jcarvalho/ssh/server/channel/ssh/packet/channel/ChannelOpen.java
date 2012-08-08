package pt.jcarvalho.ssh.server.channel.ssh.packet.channel;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.common.adt.SSHString;
import pt.jcarvalho.ssh.common.util.ByteArrayUtils;
import pt.jcarvalho.ssh.server.channel.ssh.ConnectionState;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacket;

public class ChannelOpen extends SSHPacket {

	String type;

	int channel, initialWindow, maxPacketSize;

	SSHPacket next;

	int maxPack;

	String address;

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

			keyInformation.channel = channel;

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
			next = new ChannelOpenFailure(channel,
					SSHNumbers.SSH_OPEN_UNKNOWN_CHANNEL_TYPE, "Unknown channel");
		}

		keyInformation.incomingChannels.put(channel, ConnectionState.OPEN);

		next = new ChannelOpenConf(channel, keyInformation.openNewChannel(),
				initialWindow, maxPacketSize);

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
