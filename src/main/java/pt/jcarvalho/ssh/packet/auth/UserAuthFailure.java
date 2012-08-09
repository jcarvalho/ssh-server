package pt.jcarvalho.ssh.packet.auth;

import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.adt.NameList;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ServerGenerated;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

@ServerGenerated
public class UserAuthFailure extends AbstractPacket {

    private final boolean partial;

    public UserAuthFailure(boolean part) {
	this.partial = part;
    }

    @Override
    public byte[] binaryRepresentation() {
	byte[] code = { SSHNumbers.SSH_MSG_USERAUTH_FAILURE };
	byte[] part = new byte[1];
	part[0] = (partial ? (byte) 1 : (byte) 0);

	final NameList list = new NameList("publickey,password");

	return ByteArrayUtils.concatAll(code, list.toByteArray(), part);
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
