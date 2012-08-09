package pt.jcarvalho.ssh.packet.auth;

import pt.jcarvalho.ssh.ConnectionInfo;
import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.adt.SSHString;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.packet.annotation.ClientGenerated;
import pt.jcarvalho.ssh.packet.base.Disconnect;
import pt.jcarvalho.ssh.server.SSHServer;

@ClientGenerated
public class UserAuthRequest extends AbstractPacket {

    private String username, serviceName, methodName;
    private byte[] rest;

    private SSHPacket next;

    @Override
    public byte[] binaryRepresentation() {
	return null;
    }

    @Override
    public void initWithData(byte[] data) {

	int offset = 1;

	username = new String(SSHString.extractString(data, offset));

	offset += 4 + username.length();

	serviceName = new String(SSHString.extractString(data, offset));

	offset += 4 + serviceName.length();

	methodName = new String(SSHString.extractString(data, offset));

	offset += 4 + methodName.length();

	if (offset < data.length) {
	    rest = new byte[data.length - offset];
	    System.arraycopy(data, offset, rest, 0, data.length - offset);
	}

    }

    @Override
    public String print() {
	return "UserAuth request. Username: " + username + ". Service Name: " + serviceName + ". Method name: " + methodName;
    }

    @Override
    public void process() {

	if (ConnectionInfo.get().username == null) {
	    ConnectionInfo.get().username = username;
	    ConnectionInfo.get().serviceName = serviceName;
	} else if (!ConnectionInfo.get().username.equals(username) || !ConnectionInfo.get().serviceName.equals(serviceName)) {
	    next = new Disconnect("User auth failed!", SSHNumbers.SSH_DISCONNECT_ILLEGAL_USER_NAME);
	    return;
	}

	// TODO Kerberos would go here

	if (methodName.equals("password")) {

	    if (!SSHServer.usernames.containsKey(username)) {
		next = new UserAuthFailure(false);
		return;
	    }

	    String password = new String(SSHString.extractString(rest, 1));

	    System.out.println("Password was: " + password);

	    if (SSHServer.usernames.get(username).equals(password)) {
		next = new UserAuthSuccess();
	    } else {
		next = new UserAuthFailure(false);
	    }

	} else if (methodName.equals("publickey")) {

	    // TODO Implement public key authentication

	    next = new UserAuthFailure(false);
	} else {
	    next = new UserAuthFailure(false);
	}
    }

    @Override
    public SSHPacket nextPacket() {
	return next;
    }
}
