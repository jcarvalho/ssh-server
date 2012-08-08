package pt.jcarvalho.ssh.server.channel.ssh.packet;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.common.util.ByteArrayUtils;
import pt.jcarvalho.ssh.server.channel.ssh.KeyInformation;

public class Unimplemented extends SSHPacket {

	public Unimplemented(KeyInformation keyInformation) {
		super(keyInformation);
	}

	@Override
	public byte[] binaryRepresentation() {
		byte[] res = { SSHNumbers.SSH_MSG_UNIMPLEMENTED };
		return ByteArrayUtils.concat(res,
				ByteArrayUtils.toByteArray(keyInformation.incomingSeqNumber));
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
