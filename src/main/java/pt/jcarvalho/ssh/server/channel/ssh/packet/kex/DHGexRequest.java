package pt.jcarvalho.ssh.server.channel.ssh.packet.kex;

import pt.jcarvalho.ssh.common.adt.MPInt;
import pt.jcarvalho.ssh.common.util.ByteArrayUtils;
import pt.jcarvalho.ssh.server.channel.ssh.packet.SSHPacket;

public class DHGexRequest extends SSHPacket {

	int min, n, max;
	byte[] data;
	SSHPacket next;

	@Override
	public byte[] binaryRepresentation() {
		return data;
	}

	@Override
	public String print() {
		return (keyInformation.groupExchangeMode ? "Min: " + min + ". N: " + n
				+ ". Max: " + max + "." : "DHKexInit");
	}

	@Override
	public void initWithData(byte[] data) {
		this.data = data;
		if (keyInformation.groupExchangeMode) {
			if (data.length != 13) {
				keyInformation.compatMode = true;
				n = ByteArrayUtils.toInt32(data, 1);
				min = n;
				max = n;
			} else {
				min = ByteArrayUtils.toInt32(data, 1);
				n = ByteArrayUtils.toInt32(data, 5);
				max = ByteArrayUtils.toInt32(data, 9);
			}

			keyInformation.minGroupSize = min;
			keyInformation.prefGroupSize = n;
			keyInformation.maxGroupSize = max;

			next = new DHGexGroup(keyInformation);

		} else {
			MPInt[] es = MPInt.extractMPInts(data, 1, 1);
			keyInformation.e = es[0];

			next = new DHKexReply(keyInformation);
		}

	}

	@Override
	public void process() {

	}

	@Override
	public SSHPacket nextPacket() {
		return next;
	}

}
