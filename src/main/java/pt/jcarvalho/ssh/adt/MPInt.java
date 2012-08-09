package pt.jcarvalho.ssh.adt;

import java.math.BigInteger;

import pt.jcarvalho.ssh.util.ByteArrayUtils;

public class MPInt {

    private final BigInteger value;

    private final byte[] bytes;

    /**
     * 
     * Constructor meant to be used with the actual data from the channel
     * 
     * @param data
     *            The actual Byte Array containing the MPInt
     * @param offset
     *            The offset at which the MPInt is located
     */
    public MPInt(byte[] data, int offset) {
	int len = ByteArrayUtils.toInt32(data, offset);
	offset += 4;
	byte[] val = new byte[len];
	System.arraycopy(data, offset, val, 0, len);
	this.value = new BigInteger(val);
	this.bytes = getByteArray(this.value);
    }

    /**
     * Constructor to be used when the MPInt already has a Java Representation
     * 
     * @param val
     *            The value to be represented on the MPInt
     */
    public MPInt(BigInteger value) {
	this.value = value;
	this.bytes = getByteArray(this.value);
    }

    private byte[] getByteArray(BigInteger b) {
	byte[] val = b.toByteArray();
	byte[] res = new byte[4 + val.length];
	System.arraycopy(ByteArrayUtils.toByteArray(val.length), 0, res, 0, 4);
	System.arraycopy(val, 0, res, 4, val.length);
	return res;
    }

    public BigInteger toBigInt() {
	return value;
    }

    public byte[] toByteArray() {
	return bytes;
    }

    public byte[] toByteArrayWithLeadingZeros() {

	byte[] data = value.toByteArray();

	byte[] val = data;

	if ((val[0] & 0x80) != 0) {
	    byte[] temp = new byte[data.length + 1];
	    temp[0] = '\0';
	    System.arraycopy(val, 0, temp, 1, data.length);
	    val = temp;
	}
	if (val.length == 1 && val[0] == 0) {
	    return ByteArrayUtils.toByteArray(0);
	}
	byte[] res = new byte[4 + val.length];
	System.arraycopy(ByteArrayUtils.toByteArray(val.length), 0, res, 0, 4);
	System.arraycopy(val, 0, res, 4, val.length);
	return res;
    }

}
