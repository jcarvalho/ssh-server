package pt.jcarvalho.ssh.packet.auth;

import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ServerGenerated;

@ServerGenerated
public class UserAuthSuccess extends AbstractPacket {

    @Override
    public byte[] binaryRepresentation() {
	byte[] b = { SSHNumbers.SSH_MSG_USERAUTH_SUCCESS };
	return b;
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
