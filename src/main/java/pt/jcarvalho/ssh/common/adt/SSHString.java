package pt.jcarvalho.ssh.common.adt;

import java.util.Arrays;

import pt.jcarvalho.ssh.common.util.ByteArrayUtils;

public class SSHString {

    private final byte[] data;

    public SSHString(String s) {
	this.data = s.getBytes();
    }

    public SSHString(byte[] data) {
	this.data = Arrays.copyOf(data, data.length);
    }

    @Override
    public String toString() {
	return new String(data);
    }

    public byte[] toByteArray() {
	byte[] res = new byte[data.length + 4];
	System.arraycopy(ByteArrayUtils.toByteArray(data.length), 0, res, 0, 4);
	if (data.length > 0) {
	    System.arraycopy(data, 0, res, 4, data.length);
	}
	return res;
    }

    public static byte[] byteArrayOf(String str) {

	byte[] res = new byte[str.length() + 4];
	System.arraycopy(ByteArrayUtils.toByteArray(str.length()), 0, res, 0, 4);
	if (str.length() > 0) {
	    System.arraycopy(str.getBytes(), 0, res, 4, str.length());
	}
	return res;
    }

    public static byte[] byteArrayOf(byte[] str) {

	byte[] res = new byte[str.length + 4];
	System.arraycopy(ByteArrayUtils.toByteArray(str.length), 0, res, 0, 4);
	if (str.length > 0) {
	    System.arraycopy(str, 0, res, 4, str.length);
	}
	return res;
    }

    public static byte[] extractString(byte[] data, int offset) {
	int len = ByteArrayUtils.toInt32(data, offset);
	byte[] out = new byte[len];
	System.arraycopy(data, offset + 4, out, 0, len);
	return out;
    }

}
