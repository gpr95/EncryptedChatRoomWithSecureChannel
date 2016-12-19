package server;

import java.awt.BorderLayout;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.EventQueue;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.text.DefaultCaret;

/**
 * Chat room server SWING GUI    
 */
@SuppressWarnings("serial")
public class ChatServer extends JFrame {
	/** Server socket with listener on 6664 port */
	private ServerSocket server;

	/** Logs */
	private JTextArea logTextArea;
	/** Model to JList with users - needed to write there */
	private DefaultListModel<String> listModel;

	/**
	 * Start server
	 * @param args no args needed in application
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				ChatServer serverApp = new ChatServer();
				serverApp.setVisible(true);
				serverApp.startServer();
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public ChatServer() {
		setTitle("CHAT-ROOM SERVER");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 980, 343);

		JPanel contentPane = new JPanel();
		contentPane.setBackground(Color.LIGHT_GRAY);
		contentPane.setLayout(new BorderLayout());
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);

		logTextArea = new JTextArea();
		logTextArea.setForeground(Color.DARK_GRAY);
		logTextArea.setBackground(Color.LIGHT_GRAY);
		logTextArea.setEditable(false);
		logTextArea.setLineWrap(true);
		((DefaultCaret) logTextArea.getCaret()).setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);

		JScrollPane logScrollPane = new JScrollPane(logTextArea);
		logScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		logScrollPane.setBorder(BorderFactory.createTitledBorder("Log"));
		contentPane.add(logScrollPane, BorderLayout.CENTER);

		listModel = new DefaultListModel<>();
		JList<String> listOfUsers = new JList<>(listModel);
		listOfUsers.setForeground(Color.DARK_GRAY);
		listOfUsers.setBackground(Color.LIGHT_GRAY);
		listOfUsers.setBounds(422, 10, 197, 283);

		JScrollPane listScrollPane = new JScrollPane(listOfUsers);
		listScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		listScrollPane.setBorder(BorderFactory.createTitledBorder("List of users"));
		listScrollPane.setPreferredSize(new Dimension(200, 0));
		contentPane.add(listScrollPane, BorderLayout.EAST);
	}

	/** Runs server listener and start new connection in new thread and listen other clients */
	public void startServer() {
		sysOut("---> Server start");
		Map<String, ObjectOutputStream> clientsMap = new HashMap<>();
		boolean errorOcured = false;
		try {
			server = new ServerSocket(6664, 20);
		} catch (IOException ex) {
			sysOut(ex.getMessage() + "---> Server gone down, creating sever socket failed");
			errorOcured = true;
		}

		if (!errorOcured)
			new Thread(new Runnable() {
				@Override
				public void run() {
					while (true) {
						Socket connection = null;
						try {
							connection = server.accept();
						} catch (IOException ex) {
							sysOut(ex.getMessage() + "---> Accepting clients failed");
						}
						sysOut("---> New Connection with: " + connection);
						new Thread(new ServerThread(connection, logTextArea, listModel, clientsMap)).start();
					}
				}
			}).start();
	}

	private void sysOut(String msg) {
		DateFormat dateFormat = new SimpleDateFormat("#yyyy/MM/dd HH:mm:ss#");
		Calendar cal = Calendar.getInstance();

		logTextArea.append(dateFormat.format(cal.getTime()) + " : " + msg + "\n");
	}

}
