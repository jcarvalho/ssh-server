package pt.jcarvalho.ssh.packet.channel;

import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ServerGenerated;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

@ServerGenerated
public class ChannelSuccess extends AbstractPacket {

    private int channel;

    public ChannelSuccess() {
    }

    public ChannelSuccess(int _channel) {
	channel = _channel;

    }

    @Override
    public byte[] binaryRepresentation() {
	byte[] code = { SSHNumbers.SSH_MSG_CHANNEL_SUCCESS };

	return ByteArrayUtils.concatAll(code, ByteArrayUtils.toByteArray(channel));
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
