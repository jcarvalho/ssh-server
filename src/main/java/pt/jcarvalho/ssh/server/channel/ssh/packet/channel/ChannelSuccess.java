package pt.jcarvalho.ssh.server.channel.ssh.packet.channel;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.common.util.ByteArrayUtils;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacket;

public class ChannelSuccess extends SSHPacket {

	private int channel;

	public ChannelSuccess() {
	}

	public ChannelSuccess(int _channel) {
		channel = _channel;

	}

	@Override
	public byte[] binaryRepresentation() {
		byte[] code = { SSHNumbers.SSH_MSG_CHANNEL_SUCCESS };

		return ByteArrayUtils.concatAll(code,
				ByteArrayUtils.toByteArray(channel));
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

	@Override
	public String print() {
		return "Channel success";
	}
}
