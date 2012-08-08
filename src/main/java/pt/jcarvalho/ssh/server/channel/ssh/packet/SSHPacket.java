package pt.jcarvalho.ssh.server.channel.ssh.packet;

import pt.jcarvalho.ssh.server.channel.ssh.KeyInformation;

public abstract class SSHPacket {

	protected KeyInformation keyInformation;

	public abstract byte[] binaryRepresentation();

	public String print() {
		return this.getClass().getSimpleName();
	}

	public abstract void initWithData(byte[] data);

	public abstract void process();

	public abstract SSHPacket nextPacket();

	// Due to reflection issues
	public SSHPacket() {

	}

	public boolean isLast() {
		return false;
	}

	public SSHPacket(KeyInformation keyInformation) {
		this.keyInformation = keyInformation;
	}

	public void setKeyInformation(KeyInformation keyInformation) {
		this.keyInformation = keyInformation;
	}

}
