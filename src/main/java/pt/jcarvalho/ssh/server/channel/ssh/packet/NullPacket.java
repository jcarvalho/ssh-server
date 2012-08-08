package pt.jcarvalho.ssh.server.channel.ssh.packet;

import pt.jcarvalho.ssh.common.util.ByteArrayUtils;

public class NullPacket extends SSHPacket {

	byte[] data;

	@Override
	public byte[] binaryRepresentation() {
		return null;
	}

	@Override
	public String print() {
		return "Non-recognized packet!: "
				+ ByteArrayUtils.byteArrayToHexString(data);
	}

	@Override
	public void initWithData(byte[] data) {
		this.data = data;
	}

	@Override
	public void process() {
	}

	@Override
	public SSHPacket nextPacket() {
		return new Unimplemented(keyInformation);
	}

}
