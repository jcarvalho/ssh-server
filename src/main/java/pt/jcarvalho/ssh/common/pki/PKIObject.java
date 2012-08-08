package pt.jcarvalho.ssh.common.pki;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class PKIObject implements Serializable {

	private static final long serialVersionUID = -5983751818657780186L;

	private final String serverId;
	private final String requestType;
	private final BigInteger modulus;
	private final BigInteger exponent;

	public PKIObject(String requestType, String serverId, RSAPublicKey pubKey) {
		this.requestType = requestType;
		this.serverId = serverId;
		this.modulus = pubKey.getModulus();
		this.exponent = pubKey.getPublicExponent();
	}

	public String getServerId() {
		return serverId;
	}

	public String getRequestType() {
		return requestType;
	}

	public BigInteger getModulus() {
		return modulus;
	}

	public BigInteger getExponent() {
		return exponent;
	}

}
