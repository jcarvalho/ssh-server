package pt.jcarvalho.ssh.packet.kex;

import pt.jcarvalho.ssh.ConnectionInfo;
import pt.jcarvalho.ssh.adt.MPInt;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;
import pt.jcarvalho.ssh.util.ByteArrayUtils;

public class DHGexRequest extends AbstractPacket {

    int min, n, max;
    byte[] data;
    SSHPacket next;

    @Override
    public byte[] binaryRepresentation() {
	return data;
    }

    @Override
    public String print() {
	return (ConnectionInfo.get().groupExchangeMode ? "Min: " + min + ". N: " + n + ". Max: " + max + "." : "DHKexInit");
    }

    @Override
    public void initWithData(byte[] data) {
	this.data = data;
	if (ConnectionInfo.get().groupExchangeMode) {
	    if (data.length != 13) {
		ConnectionInfo.get().compatMode = true;
		n = ByteArrayUtils.toInt32(data, 1);
		min = n;
		max = n;
	    } else {
		min = ByteArrayUtils.toInt32(data, 1);
		n = ByteArrayUtils.toInt32(data, 5);
		max = ByteArrayUtils.toInt32(data, 9);
	    }

	    ConnectionInfo.get().minGroupSize = min;
	    ConnectionInfo.get().prefGroupSize = n;
	    ConnectionInfo.get().maxGroupSize = max;

	    next = new DHGexGroup();

	} else {
	    ConnectionInfo.get().e = new MPInt(data, 1);

	    next = new DHKexReply();
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
