package pt.jcarvalho.ssh.packet;

import java.util.HashMap;
import java.util.Map;

import pt.jcarvalho.ssh.SSHNumbers;
import pt.jcarvalho.ssh.packet.auth.UserAuthRequest;
import pt.jcarvalho.ssh.packet.base.Disconnect;
import pt.jcarvalho.ssh.packet.base.Ignore;
import pt.jcarvalho.ssh.packet.base.NullPacket;
import pt.jcarvalho.ssh.packet.base.ServiceRequest;
import pt.jcarvalho.ssh.packet.base.Unimplemented;
import pt.jcarvalho.ssh.packet.channel.ChannelData;
import pt.jcarvalho.ssh.packet.channel.ChannelOpen;
import pt.jcarvalho.ssh.packet.channel.ChannelRequest;
import pt.jcarvalho.ssh.packet.channel.ChannelSuccess;
import pt.jcarvalho.ssh.packet.kex.DHGexInit;
import pt.jcarvalho.ssh.packet.kex.DHGexRequest;
import pt.jcarvalho.ssh.packet.kex.KExInitPacket;
import pt.jcarvalho.ssh.packet.kex.NewKeys;

public final class SSHPacketFactory {

    static Map<Byte, Class<? extends SSHPacket>> classes = new HashMap<>();

    static {
	classes.put(SSHNumbers.SSH_MSG_KEXINIT, KExInitPacket.class);
	classes.put(SSHNumbers.SSH_MSG_DISCONNECT, Disconnect.class);
	classes.put(SSHNumbers.SSH_MSG_KEX_DH_GEX_REQUEST, DHGexRequest.class);
	classes.put(SSHNumbers.SSH_MSG_KEX_DH_GEX_REQUEST_OLD, DHGexRequest.class);
	classes.put(SSHNumbers.SSH_MSG_KEX_DH_GEX_INIT, DHGexInit.class);
	classes.put(SSHNumbers.SSH_MSG_NEWKEYS, NewKeys.class);
	classes.put(SSHNumbers.SSH_MSG_IGNORE, Ignore.class);
	classes.put(SSHNumbers.SSH_MSG_SERVICE_REQUEST, ServiceRequest.class);
	classes.put(SSHNumbers.SSH_MSG_UNIMPLEMENTED, Unimplemented.class);
	classes.put(SSHNumbers.SSH_MSG_DEBUG, Ignore.class);
	classes.put(SSHNumbers.SSH_MSG_USERAUTH_REQUEST, UserAuthRequest.class);
	classes.put(SSHNumbers.SSH_MSG_CHANNEL_OPEN, ChannelOpen.class);
	classes.put(SSHNumbers.SSH_MSG_CHANNEL_REQUEST, ChannelRequest.class);
	classes.put(SSHNumbers.SSH_MSG_CHANNEL_SUCCESS, ChannelSuccess.class);
	classes.put(SSHNumbers.SSH_MSG_CHANNEL_DATA, ChannelData.class);
    }

    /**
     * 
     * @param data
     *            Packet received from the other end
     * 
     * @return The SSHPacket representing the binary packet received. If the
     *         packet is not recognized, an instance of NullPacket is returned.
     * 
     */
    public static SSHPacket createPacket(byte[] data) {

	SSHPacket pack = new NullPacket();

	Class<? extends SSHPacket> targetClass = classes.get(data[0]);

	if (targetClass != null) {
	    try {
		pack = targetClass.newInstance();
	    } catch (Exception e) {
		throw new RuntimeException("Error: Cannot instanciate class " + targetClass.getName(), e);
	    }
	}

	pack.initWithData(data);

	return pack;
    }
}
