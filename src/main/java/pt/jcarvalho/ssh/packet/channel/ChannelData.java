package pt.jcarvalho.ssh.packet.channel;

import java.io.UnsupportedEncodingException;

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
public class ChannelData extends AbstractPacket {

    int channel;
    byte[] data;

    public String str;

    public ChannelData() {
    }

    public ChannelData(int channel, byte[] data) {
	this.channel = channel;
	this.data = data;
    }

    @Override
    public String print() {
	return str + ". Bytes: " + ByteArrayUtils.byteArrayToHexString(str.getBytes());
    }

    public void append(byte a) {
	byte[] b = new byte[1];
	b[0] = a;
	data = ByteArrayUtils.concat(data, b);
    }

    public void removeLastN(int n) {
	byte[] newB = new byte[data.length - n];
	System.arraycopy(data, 0, newB, 0, data.length - n);
	System.arraycopy(newB, 0, data, 0, data.length - n);
	data = newB;
    }

    @Override
    public byte[] binaryRepresentation() {
	byte[] endData = data;

	try {
	    String endDataStr = new String(data, "UTF-8");
	    endData = endDataStr.replaceAll("\b", "\b \b").getBytes("UTF-8");

	} catch (UnsupportedEncodingException e) {
	    e.printStackTrace();
	}

	byte[] code = { SSHNumbers.SSH_MSG_CHANNEL_DATA };
	return ByteArrayUtils.concatAll(code, ByteArrayUtils.toByteArray(channel), SSHString.byteArrayOf(endData));
    }

    @Override
    public void initWithData(byte[] data) {
	try {
	    this.data = SSHString.extractString(data, 5);
	    String temp = new String(this.data, "UTF-8");
	    str = temp.replace((char) 0x7f, (char) 0x8);
	    this.data = str.getBytes("UTF-8");
	} catch (UnsupportedEncodingException e) {
	    e.printStackTrace();
	}
	this.channel = ConnectionInfo.get().channel;
    }

    @Override
    public void process() {

    }

    @Override
    public SSHPacket nextPacket() {
	return null;
    }

}
