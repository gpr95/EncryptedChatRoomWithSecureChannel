package server;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Map;

import javax.swing.DefaultListModel;
import javax.swing.JTextArea;

import protocol.DataPackage;
import protocol.Header;

/**
 * Chat room server - thread reflected in one client connection 
 */
public class ServerThread extends Thread {
	/** Socket to client*/
	private Socket connection;
	/** Object stream to write */
	private ObjectInputStream oInputStream;
	/** Object stream to read */
	private ObjectOutputStream oOutputStream;

	/** Client nickname reflected with that thread  */
	private String clientName;
	/** True if client is connected */
	private boolean clientConnected;
	
	/** Handler to logs area in GUI */
	private JTextArea logTextArea;

	/** Map client nickname - his object output stream */
	private Map<String, ObjectOutputStream> clientsMap;
	/** List of users in GUI to refresh new client */
	private DefaultListModel<String> listModel;

	public ServerThread(Socket connection, JTextArea logTextArea, DefaultListModel<String> listModel,
			Map<String, ObjectOutputStream> clientsMap) {
		this.connection = connection;
		this.logTextArea = logTextArea;
		this.clientsMap = clientsMap;
		this.listModel = listModel;
		clientConnected = true;
	}

	/** Start thread */
	public void run() {
		try {
			openStreams();
			getClientId();
		} catch (IOException e) {
			addToLog("Starting new connection (streams and getting nickname) failed.");
		}

		
		startUsersListRefreshingDemon();

		while (clientConnected) {
			DataPackage receivedMessage;
			try {
				receivedMessage = getMessageFromClient();
				if (receivedMessage != null)
					passResponseToOtherClient(receivedMessage);
			} catch (EOFException ex) {
				addToLog(ex.getMessage() + "---> Client " + clientName + " disconnected." + "(" + connection + ")");
				listModel.removeElement(clientName);
				clientConnected = false;
			} catch (IOException ex) {
				addToLog(ex.getMessage() + "---> Client " + clientName + " disconnected." + "(" + connection + ")");
				listModel.removeElement(clientName);
				clientConnected = false;
			}
		}
	}

	private void openStreams() throws IOException {
		oInputStream = new ObjectInputStream(connection.getInputStream());
		oOutputStream = new ObjectOutputStream(connection.getOutputStream());
		oOutputStream.flush();
	}

	private void getClientId() throws IOException {
		DataPackage dp = null;
		try {
			dp = (DataPackage) oInputStream.readObject();
			if (dp.getHeader().equals(Header.ID_SENDING))
				clientName = dp.getFromUserName();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

		listModel.addElement(clientName);
		clientsMap.put(clientName, oOutputStream);
		addToLog("New client nickname: " + clientName + " checking password.");
	}

	/** Demon which sending regularly connected clients list */
	private void startUsersListRefreshingDemon() {
		new Thread(new Runnable() {
			@Override
			public void run() {
				while (clientConnected) {
					try {
						sendUsersList();
					} catch (IOException ex) {
						addToLog("Refreshing Demon : Sending users list failed.");
						clientConnected = false;
					}

					try {
						Thread.sleep(3000);
					} catch (InterruptedException e) {
						addToLog("Refreshing Demon : Sending users demon interrupted.");
					}
				}
			}
		}).start();
	}

	private void sendUsersList() throws IOException {
		StringBuilder sb = new StringBuilder("<clients>");
		for (int i = 0; i < listModel.size(); i++)
			sb.append("<" + listModel.get(i) + ">");
		DataPackage dp = new DataPackage();
		dp.setFromUserName("SERVER");
		dp.setHeader(Header.CLIENTS_LIST);
		dp.setAdministrationMsg(sb.toString());
		sendMessage(dp);
	}

	private void passResponseToOtherClient(DataPackage receivedMessage) throws IOException {
		if (receivedMessage.getHeader().equals(Header.ID_SENDING))
			return;

		clientsMap.get(receivedMessage.getToUserName()).writeObject(receivedMessage);
	}

	private DataPackage getMessageFromClient() throws IOException {
		DataPackage message = null;
		try {
			message = (DataPackage) oInputStream.readObject();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

		return message;
	}

	private void sendMessage(DataPackage respondMsg) throws IOException {
		oOutputStream.writeObject(respondMsg);
		oOutputStream.flush();
	}

	private void addToLog(String msg) {
		DateFormat dateFormat = new SimpleDateFormat("#yyyy/MM/dd HH:mm:ss#");
		Calendar cal = Calendar.getInstance();


		logTextArea.append(dateFormat.format(cal.getTime()) + ": " + msg + "\n");
	}
}
