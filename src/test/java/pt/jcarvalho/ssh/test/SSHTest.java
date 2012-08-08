package pt.jcarvalho.ssh.test;

import java.io.IOException;

import org.junit.Test;

import pt.jcarvalho.ssh.server.SSHServer;

public class SSHTest {

    @Test
    public void testSSHServer() throws IOException {
	SSHServer server = new SSHServer(2222);
	server.run();
    }

}
