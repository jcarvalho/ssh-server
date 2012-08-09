package pt.jcarvalho.ssh.packet.channel;

import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ServerGenerated;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

@ServerGenerated
public class ChannelOpenConf extends AbstractPacket {

    private final int channel, newChannel, initialWindow, maxPacketSize;

    public ChannelOpenConf(int channel, int newChannel, int initialWindow, int maxPacketSize) {
	this.channel = channel;
	this.newChannel = newChannel;
	this.initialWindow = initialWindow;
	this.maxPacketSize = maxPacketSize;
    }

    @Override
    public byte[] binaryRepresentation() {

	byte[] code = { SSHNumbers.SSH_MSG_CHANNEL_OPEN_CONFIRMATION };

	return ByteArrayUtils.concatAll(code, ByteArrayUtils.toByteArray(channel), ByteArrayUtils.toByteArray(newChannel),
		ByteArrayUtils.toByteArray(initialWindow), ByteArrayUtils.toByteArray(maxPacketSize));
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
