package pt.jcarvalho.ssh.common.util;

import java.util.Arrays;

public class ByteArrayUtils {

    public static byte[] concatAll(byte[] first, byte[]... rest) {
	int totalLength = first.length;
	for (byte[] array : rest) {
	    totalLength += array.length;
	}
	byte[] result = Arrays.copyOf(first, totalLength);
	int offset = first.length;
	for (byte[] array : rest) {
	    System.arraycopy(array, 0, result, offset, array.length);
	    offset += array.length;
	}
	return result;
    }

    public static byte[] concat(byte[] first, byte[] second) {
	int totalLength = first.length + second.length;
	byte[] result = Arrays.copyOf(first, totalLength);
	int offset = first.length;
	System.arraycopy(second, 0, result, offset, second.length);
	return result;
    }

    public static byte[] toByteArray(int i) {
	byte[] result = new byte[4];

	result[0] = (byte) (i >> 24);
	result[1] = (byte) (i >> 16);
	result[2] = (byte) (i >> 8);
	result[3] = (byte) (i /* >> 0 */);

	return result;

    }

    public static byte[] toByteArray(byte b) {
	byte[] result = new byte[1];
	result[0] = b;
	return result;
    }

    public static int toInt32(byte[] val) {
	int value = 0;
	for (int i = 0; i < 4; i++) {
	    int shift = (4 - 1 - i) * 8;
	    value += (val[i] & 0x000000FF) << shift;
	}
	return value;
    }

    public static int toInt32(byte[] val, int offset) {
	int value = 0;
	for (int i = 0; i < 4; i++) {
	    int shift = (4 - 1 - i) * 8;
	    value += (val[i + offset] & 0x000000FF) << shift;
	}
	return value;
    }

    public static boolean toBoolean(byte[] val, int offset) {
	boolean value = false;

	value = val[offset] != 0;

	return value;
    }

    public static String byteArrayToHexString(byte[] b) {
	StringBuffer sb = new StringBuffer(b.length * 4);
	for (int i = 0; i < b.length; i++) {
	    if (i % 2 == 0) {
		sb.append(" ");
	    }
	    if (i % 16 == 0) {
		sb.append('\n');
	    }
	    int v = b[i] & 0xff;
	    if (v < 16) {
		sb.append('0');
	    }
	    sb.append(Integer.toHexString(v));
	}
	return sb.toString().toUpperCase();
    }

    public static String byteArrayToHexStringNoSpacing(byte[] b) {
	StringBuffer sb = new StringBuffer(b.length * 4);
	for (int i = 0; i < b.length; i++) {
	    int v = b[i] & 0xff;
	    if (v < 16) {
		sb.append('0');
	    }
	    sb.append(Integer.toHexString(v));
	}
	return sb.toString().toUpperCase();
    }

    public static byte[] hexToBytes(char[] hex) {
	int length = hex.length / 2;
	byte[] raw = new byte[length];
	for (int i = 0; i < length; i++) {
	    int high = Character.digit(hex[i * 2], 16);
	    int low = Character.digit(hex[i * 2 + 1], 16);
	    int value = (high << 4) | low;
	    if (value > 127)
		value -= 256;
	    raw[i] = (byte) value;
	}
	return raw;
    }

    public static byte[] hexToBytes(String hex) {
	hex = hex.toLowerCase();
	return hexToBytes(hex.toCharArray());
    }
}
