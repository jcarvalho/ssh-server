package pt.jcarvalho.ssh.packet.channel;

import pt.jcarvalho.ssh.ConnectionInfo;
import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.adt.SSHString;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ClientGenerated;
import pt.jcarvalho.ssh.packet.annotation.ServerGenerated;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

@ServerGenerated
@ClientGenerated
public class ChannelRequest extends AbstractPacket {

    String type;

    int recipientChannel, initialWindow, maxPacketSize, width_char, width_pixels, height_char, height_pixels;

    boolean wantsReply;

    SSHPacket next;

    private String term;

    private String x11auth;

    private String x11cookie;

    private byte[] data = {};

    boolean last = false;

    boolean singleConnection;

    public ChannelRequest() {
    }

    public ChannelRequest(int channel, String type, boolean wantsNext, byte[] data) {
	this.recipientChannel = channel;
	this.type = type;
	this.wantsReply = wantsNext;
	this.data = data;

    }

    @Override
    public byte[] binaryRepresentation() {

	byte[] code = { SSHNumbers.SSH_MSG_CHANNEL_REQUEST };

	byte b = (wantsReply ? (byte) 1 : (byte) 0);

	return ByteArrayUtils.concatAll(code, ByteArrayUtils.toByteArray(recipientChannel), SSHString.byteArrayOf(type),
		ByteArrayUtils.toByteArray(b), data);
    }

    @SuppressWarnings("unused")
    @Override
    public void initWithData(byte[] data) {

	int offset = 1;
	recipientChannel = ByteArrayUtils.toInt32(data, offset);
	offset += 4;
	type = new String(SSHString.extractString(data, offset));
	offset += 4 + type.length();
	wantsReply = ByteArrayUtils.toBoolean(data, offset);
	offset++;
	System.out.println("Type: " + type);
	if (type.equals("pty-req")) {
	    term = new String(SSHString.extractString(data, offset));
	    offset += 4 + term.length();
	    width_char = ByteArrayUtils.toInt32(data, offset);
	    offset += 4;
	    System.out.println(offset);
	    height_char = ByteArrayUtils.toInt32(data, offset);
	    offset += 4;

	    width_pixels = ByteArrayUtils.toInt32(data, offset);
	    offset += 4;
	    height_pixels = ByteArrayUtils.toInt32(data, offset);
	    offset += 4;
	    String encoded = new String(SSHString.extractString(data, offset));
	} else if (type.equals("x11-req")) {
	    boolean single_connection = ByteArrayUtils.toBoolean(data, offset);
	    offset++;
	    x11auth = new String(SSHString.extractString(data, offset));
	    offset += 4 + x11auth.length();
	    x11cookie = new String(SSHString.extractString(data, offset));
	    offset += 4 + x11cookie.length();
	    int screenNumber = ByteArrayUtils.toInt32(data, offset);
	    offset += 4;
	} else if (type.equals("shell")) {
	    last = true;
	} else if (type.equals("exec")) {
	    last = true;
	    ConnectionInfo.get().command = new String(SSHString.extractString(data, offset));
	}
    }

    @Override
    public void process() {

    }

    @Override
    public SSHPacket nextPacket() {
	return new ChannelSuccess(recipientChannel);
    }

    @Override
    public String print() {
	return "Channel request";
    }

    @Override
    public boolean isLast() {
	return last;
    }
}
