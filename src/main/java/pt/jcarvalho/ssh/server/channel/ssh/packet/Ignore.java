package pt.jcarvalho.ssh.server.channel.ssh.packet;

public class Ignore extends SSHPacket {

	@Override
	public byte[] binaryRepresentation() {
		return null;
	}

	@Override
	public String print() {
		return "Ignore packet";
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
