package pt.jcarvalho.ssh.server.channel.ssh.packet.auth;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.common.adt.SSHString;
import pt.jcarvalho.ssh.server.Server;
import pt.jcarvalho.ssh.server.channel.ssh.packet.Disconnect;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacket;

public class UserAuthRequest extends SSHPacket {

	String username, serviceName, methodName;
	byte[] rest;

	SSHPacket next;

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
		return "UserAuth request. Username: " + username + ". Service Name: "
				+ serviceName + ". Method name: " + methodName;
	}

	@Override
	public void process() {

		if (keyInformation.username == null) {
			keyInformation.username = username;
			keyInformation.serviceName = serviceName;
		} else if (!keyInformation.username.equals(username)
				|| !keyInformation.serviceName.equals(serviceName)) {
			next = new Disconnect("User auth failed!",
					SSHNumbers.SSH_DISCONNECT_ILLEGAL_USER_NAME);
			return;
		}

		// TODO Kerberos would go here

		if (methodName.equals("password")) {
			
			if (!Server.usernames.containsKey(username)){
				next = new UserAuthFailure(false);
				return;
			}

			String password = new String(SSHString.extractString(rest, 1));

			System.out.println("Password was: " + password);

			if (Server.usernames.get(username).equals(password)) {
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
