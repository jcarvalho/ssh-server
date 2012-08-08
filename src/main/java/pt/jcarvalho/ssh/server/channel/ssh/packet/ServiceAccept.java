package pt.jcarvalho.ssh.server.channel.ssh.packet;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.common.adt.SSHString;
import pt.jcarvalho.ssh.common.util.ByteArrayUtils;
import pt.jcarvalho.ssh.server.channel.ssh.KeyInformation;

public class ServiceAccept extends SSHPacket {
	
	SSHString type;

	public ServiceAccept(KeyInformation keyInformation, SSHString type) {
		super(keyInformation);
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
