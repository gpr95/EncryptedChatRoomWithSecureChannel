package protocol;

import java.io.Serializable;

/**
 * Data package that is sending through TCP Sockets connection. Client fills 'fromUserName' and
 * 'toUserName' parameters to give a information to the server where it
 * should send it. Header contains information about what is current stage of connection.
 * AdministrationMsg is used to sending public keys and list of users from server. 
 */
public class DataPackage implements Serializable {

	private static final long serialVersionUID = 5981242950864006099L;

	private String fromUserName;
	private String toUserName;

	private Header header;
	private String administrationMsg;
	private byte[] encryptedByteMsg;

	public String getFromUserName() {
		return fromUserName;
	}

	public void setFromUserName(String fromUserName) {
		this.fromUserName = fromUserName;
	}

	public String getToUserName() {
		return toUserName;
	}

	public void setToUserName(String to) {
		this.toUserName = to;
	}

	public String getAdministrationMsg() {
		return administrationMsg;
	}

	public void setAdministrationMsg(String stringMsg) {
		this.administrationMsg = stringMsg;
	}

	public byte[] getEncryptedMsg() {
		return encryptedByteMsg;
	}

	public void setEncryptedMsg(byte[] msg) {
		this.encryptedByteMsg = msg;
	}

	public Header getHeader() {
		return header;
	}

	public void setHeader(Header header) {
		this.header = header;
	}
}
