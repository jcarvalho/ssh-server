package pt.jcarvalho.ssh.packet.base;

import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.adt.SSHString;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ClientGenerated;

@ClientGenerated
public class ServiceRequest extends AbstractPacket {

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

	    return new ServiceAccept(new SSHString(type));

	} else if (type.equals("ssh-connection")) {

	    return new ServiceAccept(new SSHString(type));

	} else {
	    return new Disconnect("Unrecognized service request!", SSHNumbers.SSH_DISCONNECT_SERVICE_NOT_AVAILABLE);
	}

    }

}
