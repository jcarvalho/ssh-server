package pt.jcarvalho.ssh.packet.base;

import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ClientGenerated;
import pt.jcarvalho.ssh.packet.annotation.ServerGenerated;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

@ClientGenerated
@ServerGenerated
public class NullPacket extends AbstractPacket {

    byte[] data;

    @Override
    public byte[] binaryRepresentation() {
	return null;
    }

    @Override
    public String print() {
	return "Non-recognized packet!: " + ByteArrayUtils.byteArrayToHexString(data);
    }

    @Override
    public void initWithData(byte[] data) {
	this.data = data;
    }

    @Override
    public void process() {
    }

    @Override
    public SSHPacket nextPacket() {
	return new Unimplemented();
    }

}
