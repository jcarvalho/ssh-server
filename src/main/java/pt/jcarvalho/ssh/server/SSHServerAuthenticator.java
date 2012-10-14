package pt.jcarvalho.ssh.server;

import pt.jcarvalho.ssh.Authenticator;

public class SSHServerAuthenticator implements Authenticator {

    @Override
    public boolean authenticateByPassword(String username, String password) throws UnsupportedOperationException {
	System.out.println(SSHServer.usernames + " ContainsKey: " + SSHServer.usernames.containsKey(username)
		+ " password equals? " + SSHServer.usernames.get(username));
	return SSHServer.usernames.containsKey(username.trim()) && SSHServer.usernames.get(username).equals(password);
    }

    @Override
    public boolean authenticateByPublicKey(String username, byte[] publicKey) {
	throw new UnsupportedOperationException();
    }

    @Override
    public boolean authenticateByKerberos(String username, byte[] token) {
	throw new UnsupportedOperationException();
    }

}
