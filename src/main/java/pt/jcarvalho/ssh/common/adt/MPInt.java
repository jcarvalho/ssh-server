package pt.jcarvalho.ssh.common.adt;

import java.math.BigInteger;

import pt.jcarvalho.ssh.common.util.ByteArrayUtils;

public class MPInt {

	byte[] data;
	BigInteger value;

	public MPInt(String data) {
		value = new BigInteger(data);
	}

	public MPInt(String data, int radix) {
		value = new BigInteger(data, radix);
	}

	public MPInt(byte[] data) {
		this.data = data;
		value = new BigInteger(data);
	}

	public MPInt(int data) {
		value = BigInteger.valueOf(data);
	}

	public MPInt(BigInteger val) {
		value = val;
		data = this.toByteArray();
	}

	public BigInteger toBigInt() {
		return value;
	}

	public byte[] toByteArray() {
		byte[] val = value.toByteArray();
		if (val.length == 1 && val[0] == 0) {
			return ByteArrayUtils.toByteArray(0);
		}
		byte[] res = new byte[4 + val.length];
		System.arraycopy(ByteArrayUtils.toByteArray(val.length), 0, res, 0, 4);
		System.arraycopy(val, 0, res, 4, val.length);
		return res;
	}

	public byte[] toByteArrayWithLeadingZeros() {
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

	public static byte[] bytesOf(BigInteger b) {
		byte[] bytes = b.toByteArray();
		byte[] res = new byte[bytes.length + 4];
		System.arraycopy(bytes, 0, res, 4, bytes.length);
		System.arraycopy(ByteArrayUtils.toByteArray(bytes.length), 0, res, 0, 4);
		return res;
	}

	public static MPInt[] extractMPInts(byte[] data, int num, int off) {
		MPInt[] res = new MPInt[num];

		int offset = off;

		for (int i = 0; i < num; i++) {
			int len = ByteArrayUtils.toInt32(data, offset);
			offset += 4;
			byte[] val = new byte[len];
			if (len == 1)
				val[0] = data[offset];
			else
				System.arraycopy(data, offset, val, 0, len);
			res[i] = new MPInt(val);
			offset += len;
		}

		return res;
	}

}
