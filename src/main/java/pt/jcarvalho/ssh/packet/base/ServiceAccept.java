package pt.jcarvalho.ssh.packet.base;

import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.adt.SSHString;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ServerGenerated;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

@ServerGenerated
public class ServiceAccept extends AbstractPacket {

    private final SSHString type;

    public ServiceAccept(SSHString type) {
	this.type = type;
    }

    @Override
    public byte[] binaryRepresentation() {
	byte[] res = { SSHNumbers.SSH_MSG_SERVICE_ACCEPT };
	return ByteArrayUtils.concat(res, type.toByteArray());
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
