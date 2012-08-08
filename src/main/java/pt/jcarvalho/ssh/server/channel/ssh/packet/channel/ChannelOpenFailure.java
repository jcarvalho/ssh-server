package pt.jcarvalho.ssh.server.channel.ssh.packet.channel;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.common.adt.SSHString;
import pt.jcarvalho.ssh.common.util.ByteArrayUtils;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacket;

public class ChannelOpenFailure extends SSHPacket {

	String description;
	int channel, reason;

	public ChannelOpenFailure(int channel, int reason, String des) {
		this.channel = channel;
		this.reason = reason;
		this.description = des;
	}

	@Override
	public byte[] binaryRepresentation() {

		byte[] code = { SSHNumbers.SSH_MSG_CHANNEL_OPEN_FAILURE };

		return ByteArrayUtils.concatAll(code,
				ByteArrayUtils.toByteArray(channel),
				ByteArrayUtils.toByteArray(reason),
				SSHString.byteArrayOf(description), SSHString.byteArrayOf(""));
	}

	@Override
	public void initWithData(byte[] data) {

	}

	@Override
	public void process() {

	}

	@Override
	public SSHPacket nextPacket() {
		return null;
	}

}
