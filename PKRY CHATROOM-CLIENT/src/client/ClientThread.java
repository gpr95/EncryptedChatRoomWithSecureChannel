package client;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.swing.JOptionPane;
import javax.swing.JPanel;

import cipher.AES;
import cipher.DiffieHellman;
import protocol.DataPackage;
import protocol.Header;

/**
 * Chat room client - thread handling TCP connection with server
 */
public class ClientThread extends Thread 
{
	/** Handler to GUI */
	private ChatClient frameThread;

	/** Socket to server */
	private Socket connection;
	/** Client nickname */
	private String clientName;
	/** Server address info */
	private InetAddress serverAdress;
	/** Object stream to write */
	private ObjectOutputStream oOutputStream;
	/** Object stream to read */
	private ObjectInputStream oInputStream;

	/** Map that reflects user nickname with Diffie-Hellman key agreement */
	private Map<String, DiffieHellman> keyAgreement;

	/** True if something goes wrong */
	private boolean errorOccured;

	public ClientThread(String clientName, InetAddress serverAdress) 
	{
		this.clientName = clientName;
		this.serverAdress = serverAdress;
		frameThread = new ChatClient(clientName, this);
		frameThread.setVisible(true);
		errorOccured = false;
		keyAgreement = new HashMap<>();
	}

	/** Starts this thread from outside via start() method */
	public void run() 
	{
		connectToServer();
		sendClientId();
		while (!errorOccured) 
		{
			try 
			{
				DataPackage receivedMessage = getMessageFromServer();
				doActionWithMessage(receivedMessage);
			} 
			catch (EOFException ex) 
			{
				JOptionPane.showMessageDialog(frameThread, "Connection Failed", "ERROR", JOptionPane.ERROR_MESSAGE);
				errorOccured = true;
			} 
			catch (IOException ex) 
			{
				JOptionPane.showMessageDialog(frameThread, "Connection Failed", "ERROR", JOptionPane.ERROR_MESSAGE);
				errorOccured = true;
			}
		}
	}

	/**
	 * Creates connection with server on 6664 port and creates streams
	 */
	public void connectToServer() 
	{
		try 
		{
			connection = new Socket(serverAdress, 6664);
			oOutputStream = new ObjectOutputStream(connection.getOutputStream());
			oOutputStream.flush();
			oInputStream = new ObjectInputStream(connection.getInputStream());
		} 
		catch (IOException e) 
		{
			JOptionPane.showMessageDialog(frameThread, "Connection Failed", "ERROR", JOptionPane.ERROR_MESSAGE);
			errorOccured = true;
		}
	}

	/**
	 * Sends own nickname to server which will allow him to refresh all connected user lists
	 */
	private void sendClientId() 
	{
		DataPackage dp = new DataPackage();
		dp.setHeader(Header.ID_SENDING);
		dp.setFromUserName(clientName);
		try 
		{
			oOutputStream.writeObject(dp);
		} 
		catch (IOException e) 
		{
			JOptionPane.showMessageDialog(frameThread, "Sending Id Failed", "ERROR", JOptionPane.ERROR_MESSAGE);
			errorOccured = true;
		}
	}

	/**
	 * Waiting for message from server 
	 * @return DataPackage object received from server
	 * @throws IOException throw when error occur in object stream 
	 */
	private DataPackage getMessageFromServer() throws IOException
	{
		DataPackage message = null;
		try 
		{
			message = (DataPackage) oInputStream.readObject();
		} 
		catch (ClassNotFoundException e) 
		{
			JOptionPane.showMessageDialog(frameThread, "Receiving Failed", "ERROR", JOptionPane.ERROR_MESSAGE);
			errorOccured = true;
		}

		return message;
	}

	/**
	 * Parse given DataPackage and do some actions like : refreshing user list,
	 * initializing key agreement with client, showing data in GUI
	 * @param receivedMessage message that need to be parsed
	 */
	private void doActionWithMessage(DataPackage receivedMessage) 
	{
		String from = receivedMessage.getFromUserName();

		switch (receivedMessage.getHeader()) 
		{
			case CLIENTS_LIST:
				List<String> splitted = Arrays.asList(receivedMessage.getAdministrationMsg().split("[<>]+"));
				splitted = splitted.subList(2, splitted.size());
				splitted = splitted.stream().filter(i -> !i.equals(clientName)).collect(Collectors.toList());
				if (splitted.size() != frameThread.getListModel().size()) 
				{
					frameThread.getListModel().removeAllElements();
					for (int i = 0; i < splitted.size(); i++) 
					{
						frameThread.getListModel().addElement(splitted.get(i));
					}
				}
	
				break;
			case INIT:
				List<String> keys = Arrays.asList(receivedMessage.getAdministrationMsg().split("[<>]+"));
				keys = keys.subList(1, keys.size());
				DiffieHellman someoneKeyAgreement = new DiffieHellman();
				someoneKeyAgreement.setPublicVars(new BigInteger(keys.get(keys.indexOf("p") + 1)),
						new BigInteger(keys.get(keys.indexOf("g") + 1)));
				someoneKeyAgreement.randomizePrivateValue();
				someoneKeyAgreement.makeSignature();
				BigInteger tempPublicCountedValue = someoneKeyAgreement.getElgamal().getPublicComputedNumber();
				someoneKeyAgreement.setReceivedValue(new BigInteger(keys.get(keys.indexOf("B") + 1)));
				someoneKeyAgreement.setReceivedSignature1(new BigInteger(keys.get(keys.indexOf("y1") + 1)));
				someoneKeyAgreement.setReceivedSignature2(new BigInteger(keys.get(keys.indexOf("y2") + 1)));
				someoneKeyAgreement.getElgamal().setPublicComputedNumber(new BigInteger(keys.get(keys.indexOf("b") + 1)));
				someoneKeyAgreement.checkSignature();
				someoneKeyAgreement.getElgamal().setPublicComputedNumber(tempPublicCountedValue);
				someoneKeyAgreement.generateKey();
				if (frameThread.getTabbedPane().indexOfTab(from) == -1) 
				{
					JPanel panel = frameThread.generatePanelForTab();
					frameThread.getTabbedPane().addTab(from, panel);
					
	
					try 
					{
						DataPackage dp = new DataPackage();
						dp.setFromUserName(clientName);
						dp.setToUserName(from);
						dp.setHeader(Header.BACKWARD_INIT);
						dp.setAdministrationMsg("<p><" + someoneKeyAgreement.getP() + ">" + 
								"<g><" + someoneKeyAgreement.getG() + ">" + 
								"<B><" + someoneKeyAgreement.getA() + ">" + 
								"<y1><" + someoneKeyAgreement.getElgamal().getSendingFirstValue() + ">" +
								"<y2><" + someoneKeyAgreement.getElgamal().getSendingSecondValue() + ">" + 
								"<b><" + tempPublicCountedValue + ">");
						oOutputStream.writeObject(dp);
						oOutputStream.flush();
						keyAgreement.put(from, someoneKeyAgreement);
	
					} 
					catch (IOException e) 
					{
						JOptionPane.showMessageDialog(frameThread, "Sending init backward Failed", "ERROR",
								JOptionPane.ERROR_MESSAGE);
					}
					frameThread.showMessage(from, from + " has started conversation.",! keyAgreement.get(from).isAuthorized());
				}
	
				break;
			case BACKWARD_INIT:
				List<String> key = Arrays.asList(receivedMessage.getAdministrationMsg().split("[<>]+"));
				key = key.subList(1, key.size());
				keyAgreement.get(from).setPublicVars(new BigInteger(key.get(key.indexOf("p") + 1)),
						new BigInteger(key.get(key.indexOf("g") + 1)));
				keyAgreement.get(from).setReceivedValue(new BigInteger(key.get(key.indexOf("B") + 1)));
				keyAgreement.get(from).setReceivedSignature1(new BigInteger(key.get(key.indexOf("y1") + 1)));
				keyAgreement.get(from).setReceivedSignature2(new BigInteger(key.get(key.indexOf("y2") + 1)));
				keyAgreement.get(from).getElgamal().setPublicComputedNumber(new BigInteger(key.get(key.indexOf("b") + 1)));
				
				keyAgreement.get(from).checkSignature();
				keyAgreement.get(from).generateKey();
				break;
			case DESTROY:
				if (frameThread.getTabbedPane().indexOfTab(from) != -1) 
				{
					frameThread.removeTabAndReferences(from);
					keyAgreement.remove(from);
				}
	
				break;
			case MSG:
				AES aes = new AES();
				frameThread.showMessage(from,
						new String(aes.decrypt(receivedMessage.getEncryptedMsg(), keyAgreement.get(from).getKeyBytes())),
						!keyAgreement.get(from).isAuthorized());
				break;
			default:
				break;
		}
	}

	/**
	 * Initializing Diffie-Hellman key agreement with given user
	 * @param userNameTo nickname of user name with whom need to be initialized key
	 */
	public void initializeCommunication(String userNameTo) 
	{
		DiffieHellman myKeyAgreement = new DiffieHellman();
		myKeyAgreement.generatePublicVars();
		myKeyAgreement.randomizePrivateValue();
		myKeyAgreement.makeSignature();

		DataPackage dp = new DataPackage();
		dp.setFromUserName(clientName);
		dp.setToUserName(userNameTo);
		dp.setHeader(Header.INIT);
		dp.setAdministrationMsg("<p><" + myKeyAgreement.getP() + ">" + 
								"<g><" + myKeyAgreement.getG() + ">" + 
								"<B><"+ myKeyAgreement.getA() + ">" + 
								"<y1><"+ myKeyAgreement.getElgamal().getSendingFirstValue() + ">" + 
								"<y2><"+ myKeyAgreement.getElgamal().getSendingSecondValue() + ">" +
								"<b><"+ myKeyAgreement.getElgamal().getPublicComputedNumber() + ">");
		try 
		{
			oOutputStream.writeObject(dp);
			oOutputStream.flush();

			keyAgreement.put(userNameTo, myKeyAgreement);
		} 
		catch (IOException e) 
		{
			JOptionPane.showMessageDialog(frameThread, "Sending init Failed", "ERROR", JOptionPane.ERROR_MESSAGE);
			errorOccured = true;
		}
	}

	/**
	 * Makes encryption of given message from user via AES with Diffie-Hellman symetric key
	 * @param userNameTo Nickname of user that sends that message
	 * @param msg Message
	 * @throws IOException thrown when error occur in object stream
	 */
	public void encryptAndSendMessage(String userNameTo, String msg) throws IOException 
	{
		AES aes = new AES();
		DataPackage dp = new DataPackage();
		dp.setFromUserName(clientName);
		dp.setToUserName(userNameTo);
		dp.setHeader(Header.MSG);
		dp.setEncryptedMsg(aes.encrypt(msg.getBytes(), keyAgreement.get(userNameTo).getKeyBytes()));
		try 
		{
			oOutputStream.writeObject(dp);
			oOutputStream.flush();
		} 
		catch (IOException e) 
		{
			JOptionPane.showMessageDialog(frameThread, "Sending msg Failed", "ERROR", JOptionPane.ERROR_MESSAGE);
			errorOccured = true;
		}
	}

	/**
	 * Initializing communication to close conversation between users
	 * @param userNameTo nickname of user which whom conversation is ending
	 */
	public void destroyingCommunication(String userNameTo) 
	{
		DataPackage dp = new DataPackage();
		dp.setFromUserName(clientName);
		dp.setToUserName(userNameTo);
		dp.setHeader(Header.DESTROY);
		try 
		{
			oOutputStream.writeObject(dp);
			oOutputStream.flush();
		} 
		catch (IOException e) 
		{
			JOptionPane.showMessageDialog(frameThread, "Sending destroy Failed", "ERROR", JOptionPane.ERROR_MESSAGE);
			errorOccured = true;
		}
		keyAgreement.remove(userNameTo);
	}
}
