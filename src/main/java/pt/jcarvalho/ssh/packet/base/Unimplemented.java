package pt.jcarvalho.ssh.packet.base;

import pt.jcarvalho.ssh.ConnectionInfo;
import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ClientGenerated;
import pt.jcarvalho.ssh.packet.annotation.ServerGenerated;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

@ServerGenerated
@ClientGenerated
public class Unimplemented extends AbstractPacket {

    @Override
    public byte[] binaryRepresentation() {
	byte[] res = { SSHNumbers.SSH_MSG_UNIMPLEMENTED };
	return ByteArrayUtils.concat(res, ByteArrayUtils.toByteArray(ConnectionInfo.get().incomingSeqNumber));
    }

    @Override
    public String print() {
	return null;
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
