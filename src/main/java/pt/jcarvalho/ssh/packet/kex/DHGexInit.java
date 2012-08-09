package pt.jcarvalho.ssh.packet.kex;

import pt.jcarvalho.ssh.ConnectionInfo;
import pt.jcarvalho.ssh.adt.MPInt;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;

public class DHGexInit extends AbstractPacket {

    @Override
    public byte[] binaryRepresentation() {
	return null;
    }

    @Override
    public void initWithData(byte[] data) {
	ConnectionInfo.get().e = new MPInt(data, 1);
    }

    @Override
    public void process() {
    }

    @Override
    public SSHPacket nextPacket() {
	return new DHGexReply();
    }

}
