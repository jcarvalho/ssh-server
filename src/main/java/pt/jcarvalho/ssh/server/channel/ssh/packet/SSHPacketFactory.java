package pt.jcarvalho.ssh.server.channel.ssh.packet;

import java.util.HashMap;
import java.util.Map;

import pt.jcarvalho.ssh.common.SSHNumbers;
import pt.jcarvalho.ssh.server.channel.ssh.KeyInformation;
import pt.jcarvalho.ssh.server.channel.ssh.packet.auth.UserAuthRequest;
import pt.jcarvalho.ssh.server.channel.ssh.packet.channel.ChannelData;
import pt.jcarvalho.ssh.server.channel.ssh.packet.channel.ChannelOpen;
import pt.jcarvalho.ssh.server.channel.ssh.packet.channel.ChannelRequest;
import pt.jcarvalho.ssh.server.channel.ssh.packet.channel.ChannelSuccess;
import pt.jcarvalho.ssh.server.channel.ssh.packet.kex.DHGexInit;
import pt.jcarvalho.ssh.server.channel.ssh.packet.kex.DHGexRequest;
import pt.jcarvalho.ssh.server.channel.ssh.packet.kex.KExInitPacket;
import pt.jcarvalho.ssh.server.channel.ssh.packet.kex.NewKeys;

public final class SSHPacketFactory {

	static Map<Byte, Class<? extends SSHPacket>> classes = new HashMap<Byte, Class<? extends SSHPacket>>();

	static {
		classes.put(SSHNumbers.SSH_MSG_KEXINIT, KExInitPacket.class);
		classes.put(SSHNumbers.SSH_MSG_DISCONNECT, Disconnect.class);
		classes.put(SSHNumbers.SSH_MSG_KEX_DH_GEX_REQUEST, DHGexRequest.class);
		classes.put(SSHNumbers.SSH_MSG_KEX_DH_GEX_REQUEST_OLD,
				DHGexRequest.class);
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

	public static SSHPacket processPacket(byte[] data,
			KeyInformation keyInformation) {
		SSHPacket pack = new NullPacket();
		Class<? extends SSHPacket> targetClass = classes.get(data[0]);
		if (targetClass != null) {
			try {
				pack = targetClass.newInstance();
			} catch (Exception e) {
			}
		}

		pack.setKeyInformation(keyInformation);
		pack.initWithData(data);
		return pack;
	}

}
