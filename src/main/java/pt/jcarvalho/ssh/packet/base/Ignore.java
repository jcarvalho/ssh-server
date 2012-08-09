package pt.jcarvalho.ssh.packet.base;

import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ClientGenerated;
import pt.jcarvalho.ssh.packet.annotation.ServerGenerated;

@ClientGenerated
@ServerGenerated
public class Ignore extends AbstractPacket {

    @Override
    public byte[] binaryRepresentation() {
	return null;
    }

    @Override
    public String print() {
	return "Ignore packet";
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
