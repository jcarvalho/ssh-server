package pt.jcarvalho.ssh.packet.channel;

import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.adt.SSHString;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ServerGenerated;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

@ServerGenerated
public class ChannelOpenFailure extends AbstractPacket {

    private final String description;
    private final int channel, reason;

    public ChannelOpenFailure(int channel, int reason, String des) {
	this.channel = channel;
	this.reason = reason;
	this.description = des;
    }

    @Override
    public byte[] binaryRepresentation() {

	byte[] code = { SSHNumbers.SSH_MSG_CHANNEL_OPEN_FAILURE };

	return ByteArrayUtils.concatAll(code, ByteArrayUtils.toByteArray(channel), ByteArrayUtils.toByteArray(reason),
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
