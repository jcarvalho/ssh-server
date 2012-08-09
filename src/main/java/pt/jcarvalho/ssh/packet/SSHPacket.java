package pt.jcarvalho.ssh.packet;

public interface SSHPacket {

    /**
     * Called when the packet is to be transmitted to the other end.
     * 
     * @return The binary representation of the packet
     */
    public byte[] binaryRepresentation();

    /**
     * Description of the packet
     * 
     * @return
     */
    public String print();

    /**
     * Called when the object was created by the packet factory, allowing
     * initializations from the packet's binary representation
     * 
     * @param data
     *            The binary representation of the packet
     */
    public void initWithData(byte[] data);

    public void process();

    /**
     * The packet to be sent in response to this packet.
     * 
     * @return The response. If this is null, no response will be sent to the
     *         other end
     */
    public SSHPacket nextPacket();

    /**
     * Determines whether upon receiving this packet the connection should be
     * closed.
     * 
     * @return
     */
    public boolean isLast();

}