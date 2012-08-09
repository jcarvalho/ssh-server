package pt.jcarvalho.ssh;

public interface MAC {

    public void setKey(byte[] key) throws MacException;

    public byte[] generateCode(byte[] data);

    public int macBytes();

    public static class MacException extends Exception {

	private static final long serialVersionUID = 6183207852138134537L;

	public MacException(Exception e) {
	    super(e);
	}

    }

}