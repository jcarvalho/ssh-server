package pt.jcarvalho.ssh.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import pt.jcarvalho.ssh.common.util.Security;
import pt.jcarvalho.ssh.server.connector.Connector;

public class SSHServer {

    public static Map<String, String> usernames = new HashMap<String, String>();

    static {
	usernames.put("joaocarvalho", "password");
	usernames.put("guest", "password");
    }

    private final Executor executor;

    private final int port;

    public SSHServer(int port) {
	this.port = port;
	this.executor = Executors.newCachedThreadPool();
    }

    public void run() throws IOException {
	Security.generateKeys();

	try (ServerSocket socket = new ServerSocket(port)) {
	    System.out.println("- WAITING FOR CONNECTIONS -");
	    while (true) {
		Socket sock = socket.accept();
		System.out.println("- Accepted Connection from " + sock + " -");
		executor.execute(new Connector(sock));
	    }
	}
    }

}
