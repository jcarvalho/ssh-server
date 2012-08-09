package pt.jcarvalho.ssh;

public class SSHNumbers {

    /**
     * Message numbers
     */

    /**
     * Initial assignments of the Message ID values
     */

    public static final byte SSH_MSG_DISCONNECT = 1;
    public static final byte SSH_MSG_IGNORE = 2;
    public static final byte SSH_MSG_UNIMPLEMENTED = 3;
    public static final byte SSH_MSG_DEBUG = 4;
    public static final byte SSH_MSG_SERVICE_REQUEST = 5;
    public static final byte SSH_MSG_SERVICE_ACCEPT = 6;
    public static final byte SSH_MSG_KEXINIT = 20;
    public static final byte SSH_MSG_NEWKEYS = 21;
    public static final byte SSH_MSG_USERAUTH_REQUEST = 50;
    public static final byte SSH_MSG_USERAUTH_FAILURE = 51;
    public static final byte SSH_MSG_USERAUTH_SUCCESS = 52;
    public static final byte SSH_MSG_USERAUTH_BANNER = 53;
    public static final byte SSH_MSG_GLOBAL_REQUEST = 80;
    public static final byte SSH_MSG_REQUEST_SUCCESS = 81;
    public static final byte SSH_MSG_REQUEST_FAILURE = 82;
    public static final byte SSH_MSG_CHANNEL_OPEN = 90;
    public static final byte SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
    public static final byte SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
    public static final byte SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
    public static final byte SSH_MSG_CHANNEL_DATA = 94;
    public static final byte SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
    public static final byte SSH_MSG_CHANNEL_EOF = 96;
    public static final byte SSH_MSG_CHANNEL_CLOSE = 97;
    public static final byte SSH_MSG_CHANNEL_REQUEST = 98;
    public static final byte SSH_MSG_CHANNEL_SUCCESS = 99;
    public static final byte SSH_MSG_CHANNEL_FAILURE = 100;

    /**
     * Disconnection messages
     */

    public static final byte SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1;
    public static final byte SSH_DISCONNECT_PROTOCOL_ERROR = 2;
    public static final byte SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3;
    public static final byte SSH_DISCONNECT_RESERVED = 4;
    public static final byte SSH_DISCONNECT_MAC_ERROR = 5;
    public static final byte SSH_DISCONNECT_COMPRESSION_ERROR = 6;
    public static final byte SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
    public static final byte SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
    public static final byte SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9;
    public static final byte SSH_DISCONNECT_CONNECTION_LOST = 10;
    public static final byte SSH_DISCONNECT_BY_APPLICATION = 11;
    public static final byte SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12;
    public static final byte SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
    public static final byte SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
    public static final byte SSH_DISCONNECT_ILLEGAL_USER_NAME = 15;

    /**
     * Channel connection failure reason codes
     */

    public static final int SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
    public static final int SSH_OPEN_CONNECT_FAILED = 2;
    public static final int SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
    public static final int SSH_OPEN_RESOURCE_SHORTAGE = 4;

    /**
     * Diffie-Hellman Key Exchange Message numbers
     */

    public static final byte SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30;
    public static final byte SSH_MSG_KEX_DH_GEX_REQUEST = 34;
    public static final byte SSH_MSG_KEX_DH_GEX_GROUP = 31;
    public static final byte SSH_MSG_KEX_DH_GEX_INIT = 32;
    public static final byte SSH_MSG_KEX_DH_GEX_REPLY = 33;

    public static final byte SSH_MSG_KEXDH_REPLY = 31;
}
