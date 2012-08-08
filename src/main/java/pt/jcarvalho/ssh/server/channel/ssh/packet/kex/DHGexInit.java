package pt.jcarvalho.ssh.server.channel.ssh.packet.kex;

import pt.jcarvalho.ssh.common.adt.MPInt;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacket;

public class DHGexInit extends SSHPacket {
	
	@Override
	public byte[] binaryRepresentation() {
		return null;
	}

	@Override
	public void initWithData(byte[] data) {
		MPInt[] es = MPInt.extractMPInts(data, 1, 1);
		keyInformation.e = es[0];
	}

	@Override
	public void process() {
	}

	@Override
	public SSHPacket nextPacket() {
		return new DHGexReply(keyInformation);
	}

}
