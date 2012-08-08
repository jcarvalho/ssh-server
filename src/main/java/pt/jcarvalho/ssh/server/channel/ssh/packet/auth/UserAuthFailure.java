package pt.jcarvalho.ssh.server.channel.ssh.packet.auth;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.common.adt.NameList;
import pt.jcarvalho.ssh.common.util.ByteArrayUtils;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacket;

public class UserAuthFailure extends SSHPacket {

    boolean partial;

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
