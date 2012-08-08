package pt.jcarvalho.ssh.server.channel.ssh.packet;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.common.adt.SSHString;

public class ServiceRequest extends SSHPacket {

	String type;

	@Override
	public byte[] binaryRepresentation() {
		return null;
	}

	@Override
	public String print() {
		return "Received request: " + type;
	}

	@Override
	public void initWithData(byte[] data) {
		byte[] str = new byte[data.length - 5];
		System.arraycopy(data, 5, str, 0, data.length - 5);
		type = new String(str);
	}

	@Override
	public void process() {

	}

	@Override
	public SSHPacket nextPacket() {

		if (type.equals("ssh-userauth")) {

			return new ServiceAccept(keyInformation, new SSHString(type));

		} else if (type.equals("ssh-connection")) {

			return new ServiceAccept(keyInformation, new SSHString(type));

		} else {
			return new Disconnect("Unrecognized service request!",
					SSHNumbers.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE);
		}

	}

}
