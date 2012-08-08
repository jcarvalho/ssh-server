package pt.jcarvalho.ssh.server.channel.ssh.packet.auth;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacket;

public class UserAuthSuccess extends SSHPacket {

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
