package pt.jcarvalho.ssh.adt;

import java.util.LinkedList;
import java.util.List;

import pt.jcarvalho.ssh.util.ByteArrayUtils;

public class NameList {

    private final List<String> strs = new LinkedList<String>();
    private final String all;

    public NameList(String s) {
	this.all = s;
	String[] names = s.split(",");
	for (String name : names) {
	    strs.add(name);
	}
    }

    public int getTotalLength() {
	return 4 + all.length();
    }

    public List<String> getNames() {
	return strs;
    }

    public String getAll() {
	return all;
    }

    public byte[] toByteArray() {
	if (all.length() == 0) {
	    return ByteArrayUtils.toByteArray(0);
	}
	byte[] result = new byte[all.length() + 4];
	System.arraycopy(ByteArrayUtils.toByteArray(all.length()), 0, result, 0, 4);
	System.arraycopy(all.getBytes(), 0, result, 4, all.length());
	return result;
    }

    public static NameList[] extractNameLists(byte[] from, int offset, int numLists) {
	NameList[] lists = new NameList[numLists];

	for (int i = 0; i < numLists; i++) {
	    int length = ByteArrayUtils.toInt32(from, offset);
	    byte[] list = new byte[length];
	    System.arraycopy(from, offset + 4, list, 0, length);
	    lists[i] = new NameList(new String(list));
	    offset += length + 4;
	}

	return lists;
    }

}
