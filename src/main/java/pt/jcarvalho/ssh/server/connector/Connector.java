package pt.jcarvalho.ssh.server.connector;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;

import pt.jcarvalho.ssh.server.channel.SecureChannel;
import pt.jcarvalho.ssh.server.channel.exception.SecureChannelException;
import pt.jcarvalho.ssh.server.channel.ssh.SSHSecureChannel;

public class Connector implements Runnable {

    Socket socket;
    SecureChannel channel;

    public Connector(Socket socket) {
	this.socket = socket;
	this.channel = new SSHSecureChannel(socket);
    }

    private void execute(String command) throws IOException, SecureChannelException {
	Process proc = null;
	try {
	    proc = Runtime.getRuntime().exec(command);
	} catch (IOException e) {
	    channel.write("Cannot execute command: " + command);
	    return;
	}
	InputStream in = proc.getInputStream();
	InputStreamReader inst = new InputStreamReader(in);
	BufferedReader buf = new BufferedReader(inst);
	String lin;
	StringBuffer sb = new StringBuffer();
	while ((lin = buf.readLine()) != null) {
	    sb.append(lin);
	    sb.append("\r\n");
	}
	BufferedReader buffErr = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
	while ((lin = buffErr.readLine()) != null) {
	    sb.append(lin);
	    sb.append("\r\n");
	}
	channel.write(sb.toString());

    }

    @Override
    public void run() {

	try {
	    String input = channel.setup();
	    if (input != null) {
		System.out.println("Exec Mode");
		execute(input);
	    } else {
		System.out.println("Shell Mode");
		channel.write("Welcome to the SIRS SSH server!");

		String line;

		while ((line = channel.readLine()) != null) {

		    String[] opts = line.split("\\ ");

		    if (opts[0].equalsIgnoreCase("quit")) {
			channel.write("Now quitting. So long and thanks for all the fish!");
			break;
		    } else if (opts[0].trim().length() == 0) {
			channel.write("");
		    } else if (opts[0].equalsIgnoreCase("hello")) {
			execute("bash /speak.sh 'Hello and welcome to our presentation'");
			channel.write("Hello there, I'm the SIRS SSH server powered by group 2.");
		    } else
			execute(line);
		}

	    }

	    channel.close(0);

	} catch (IOException e) {
	    e.printStackTrace();
	} finally {
	    if (!socket.isClosed()) {
		try {
		    socket.close();
		} catch (IOException e) {
		}
	    }
	    System.out.println("- Closing connection from socket " + socket + " -");
	}
    }
}
