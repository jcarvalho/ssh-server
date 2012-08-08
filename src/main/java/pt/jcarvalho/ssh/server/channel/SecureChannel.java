package pt.jcarvalho.ssh.server.channel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import pt.jcarvalho.ssh.server.channel.exception.SecureChannelException;

public abstract class SecureChannel {

	protected InputStream input;
	protected OutputStream output;
	protected Socket socket;

	public SecureChannel(Socket socket) {
		this.socket = socket;
	}

	public String setUp() throws IOException, SecureChannelException {
		this.input = socket.getInputStream();
		this.output = socket.getOutputStream();
		return doSetup();
	}

	public abstract String doSetup() throws IOException, SecureChannelException;

	public abstract String readLine() throws IOException,
			SecureChannelException;

	public abstract void write(String string) throws IOException,
			SecureChannelException;

	public abstract void close(int code) throws IOException,
			SecureChannelException;

}
