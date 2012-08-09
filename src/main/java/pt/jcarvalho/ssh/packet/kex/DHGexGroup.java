package pt.jcarvalho.ssh.packet.kex;

import java.math.BigInteger;

import pt.jcarvalho.ssh.ConnectionInfo;
import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.adt.MPInt;
import pt.jcarvalho.ssh.packet.AbstractPacket;
import pt.jcarvalho.ssh.packet.SSHPacket;

public class DHGexGroup extends AbstractPacket {

    // P and G are fixed as suggested by the professor
    @Override
    public byte[] binaryRepresentation() {

	byte[] pBytes = { (byte) 0x00, (byte) 0xde, (byte) 0x49, (byte) 0xfc, (byte) 0x90, (byte) 0x69, (byte) 0x99, (byte) 0x4c,
		(byte) 0x37, (byte) 0x9d, (byte) 0x2b, (byte) 0x65, (byte) 0x63, (byte) 0xef, (byte) 0xd3, (byte) 0x7e,
		(byte) 0xfa, (byte) 0xe6, (byte) 0x78, (byte) 0x5e, (byte) 0xeb, (byte) 0x1d, (byte) 0xd0, (byte) 0xa1,
		(byte) 0x2b, (byte) 0x09, (byte) 0x0a, (byte) 0xac, (byte) 0x27, (byte) 0x2b, (byte) 0x22, (byte) 0xdf,
		(byte) 0x8c, (byte) 0x64, (byte) 0xa4, (byte) 0xa2, (byte) 0xab, (byte) 0x7b, (byte) 0x99, (byte) 0xce,
		(byte) 0x0b, (byte) 0x77, (byte) 0xa9, (byte) 0xa5, (byte) 0x2e, (byte) 0x08, (byte) 0x33, (byte) 0xd5,
		(byte) 0x2d, (byte) 0x53, (byte) 0xb2, (byte) 0x58, (byte) 0xce, (byte) 0xdf, (byte) 0xfd, (byte) 0x17,
		(byte) 0x5d, (byte) 0xc8, (byte) 0xa3, (byte) 0x76, (byte) 0x6a, (byte) 0x9b, (byte) 0x98, (byte) 0x07,
		(byte) 0x36, (byte) 0x26, (byte) 0x46, (byte) 0xdc, (byte) 0x92, (byte) 0x15, (byte) 0x62, (byte) 0x8c,
		(byte) 0x3f, (byte) 0x4a, (byte) 0xf0, (byte) 0xe0, (byte) 0x8d, (byte) 0x00, (byte) 0xab, (byte) 0x60,
		(byte) 0xa3, (byte) 0xb9, (byte) 0xe5, (byte) 0x5b, (byte) 0xae, (byte) 0x47, (byte) 0xe8, (byte) 0x26,
		(byte) 0x51, (byte) 0xda, (byte) 0x0c, (byte) 0x15, (byte) 0xa2, (byte) 0x73, (byte) 0x55, (byte) 0xdd,
		(byte) 0xb0, (byte) 0x63, (byte) 0x65, (byte) 0xca, (byte) 0xe1, (byte) 0xdd, (byte) 0xde, (byte) 0x4c,
		(byte) 0x0c, (byte) 0x97, (byte) 0xdc, (byte) 0x99, (byte) 0x42, (byte) 0xfd, (byte) 0x65, (byte) 0xe9,
		(byte) 0x86, (byte) 0x7f, (byte) 0xa5, (byte) 0x0e, (byte) 0x72, (byte) 0xe1, (byte) 0xc7, (byte) 0x85,
		(byte) 0x41, (byte) 0x1e, (byte) 0xdd, (byte) 0x28, (byte) 0xde, (byte) 0x27, (byte) 0x9c, (byte) 0x7b,
		(byte) 0x37 };

	byte[] gBytes = { (byte) 0x05 };

	ConnectionInfo.get().p = new MPInt(new BigInteger(pBytes));
	ConnectionInfo.get().g = new MPInt(new BigInteger(gBytes));

	byte[] pB = ConnectionInfo.get().p.toByteArray();
	byte[] gB = ConnectionInfo.get().g.toByteArray();

	int totalLen = 1 + pB.length + gB.length;

	byte[] res = new byte[totalLen];
	res[0] = SSHNumbers.SSH_MSG_KEX_DH_GEX_GROUP;
	System.arraycopy(pB, 0, res, 1, pB.length);
	System.arraycopy(gB, 0, res, 1 + pB.length, gB.length);
	return res;
    }

    @Override
    public void initWithData(byte[] data) {
    }

    @Override
    public void process() {

    }

    @Override
    public SSHPacket nextPacket() {
	return null;
    }

}
