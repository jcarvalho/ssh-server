package pt.jcarvalho.ssh.packet;

/**
 * SuperClass for all SSH Packets.
 * 
 */
public abstract class AbstractPacket implements SSHPacket {

    @Override
    public String print() {
	return this.getClass().getSimpleName();
    }

    @Override
    public boolean isLast() {
	return false;
    }

}
