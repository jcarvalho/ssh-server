package pt.jcarvalho.ssh.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

import pt.jcarvalho.ssh.common.exception.PKIException;
import pt.jcarvalho.ssh.common.pki.PKIConnector;
import pt.jcarvalho.ssh.common.pki.PKIObject;
import pt.jcarvalho.ssh.common.util.Security;
import pt.jcarvalho.ssh.server.connector.Connector;

public class Server {

    public static Map<String, String> usernames = new HashMap<String, String>();

    static {
	usernames.put("joaocarvalho", "password");
	usernames.put("alourenco", "pass");
	usernames.put("ricardo", "password");
	usernames.put("guest", "password");
    }

    int port;

    public Server(int port) {
	this.port = port;
    }

    public void run() throws IOException {
	Security.generateKeys();

	final String serverId = "SSH-2.0-SIRSssh_0.1:" + port;

	PKIObject obj = new PKIObject("Register", serverId, Security.getRsaPub());
	try {
	    PKIConnector.sendRequest(obj, "127.0.0.1");
	} catch (PKIException e) {
	    System.out.println("WARNING: PKI server Unavailable! Reason: " + e.getMessage());
	}

	ServerSocket socket = new ServerSocket(port);
	System.out.println("- WAITING FOR CONNECTIONS -");
	while (true) {
	    Socket sock = socket.accept();
	    System.out.println("- Accepted Connection from " + sock + " -");
	    (new Thread(new Connector(sock))).start();
	}
    }

    public static void main(String[] args) {
	if (args.length < 1) {
	    System.out.println("Syntax: java Server <port>");
	    System.exit(-1);
	}
	int port = Integer.parseInt(args[0]);
	System.out.println("-- SIRS SSH Server STARTING --");
	Server serv = new Server(port);

	try {
	    serv.run();
	} catch (IOException e) {
	    System.out.println("-- SIRS SSH Server FOUND ERROR: " + e + " --");
	} finally {
	    System.out.println("-- SIRS SSH Server CLOSING --");
	}
    }

}
