package pt.jcarvalho.ssh.packet.base;

import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.adt.SSHString;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ClientGenerated;
import pt.jcarvalho.ssh.packet.annotation.ServerGenerated;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

@ServerGenerated
@ClientGenerated
public class Disconnect extends AbstractPacket {

    private String message;
    private byte reason;

    public Disconnect(String message, byte reason) {
	this.message = message;
	this.reason = reason;
    }

    public Disconnect() {

    }

    @Override
    public byte[] binaryRepresentation() {
	byte[] res = { SSHNumbers.SSH_MSG_DISCONNECT, reason };
	return ByteArrayUtils.concatAll(res, message.getBytes(), new SSHString("").toByteArray());
    }

    @Override
    public String print() {
	return "SSH_MSG_DISCONNECT received: " + message + ". Reason: " + reason;
    }

    @Override
    public void initWithData(byte[] data) {
	byte[] msg = new byte[data.length - 1];
	reason = data[1];
	System.arraycopy(data, 2, msg, 0, data.length - 2);
	message = new String(msg);
    }

    @Override
    public void process() {

    }

    @Override
    public SSHPacket nextPacket() {
	return null;
    }

    @Override
    public boolean isLast() {
	return true;
    }

}
