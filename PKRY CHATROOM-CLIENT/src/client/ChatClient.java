package client;

import java.awt.BorderLayout;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.SystemColor;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.text.DefaultCaret;

/**
 * Chat room client SWING GUI  
 */
@SuppressWarnings("serial")
public class ChatClient extends JFrame 
{
	/** 
	 * Networking thread handler - needed to initialize methods 
	 * reflected with needed TCP connection to the server 
	 */
	private ClientThread networkingThread;

	/** Client nickname */
	private String clientName;

	/** 
	 * TabbedPane handler needed to swich between tabs when someone
	 * is initializing connection 
	 */
	private JTabbedPane tabbedPane;
	/** List of users given by server */
	private JList<String> listOfUsers;
	/** Handler to users list model given to TCP thread to write there */
	private DefaultListModel<String> listModel;

	/** Handlers to sending text area reflected with all tabs */
	private Map<Integer, JTextArea> handlers;

	/**
	 * Constructor
	 * @param clientName needed client nickname to the application
	 * @param networkingThread thread with tcp connection to the server
	 */
	public ChatClient(String clientName, ClientThread networkingThread)
	{
		this();
		this.clientName = clientName;
		this.networkingThread = networkingThread;
		handlers = new HashMap<>();
		setTitle("CHAT CLIENT - " + clientName);
	}

	public ChatClient()
	{
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 845, 343);
		setBackground(Color.DARK_GRAY);
		
		Dimension dimension = Toolkit.getDefaultToolkit().getScreenSize();
	    int x = (int) ((dimension.getWidth() - getWidth()) / 2);
	    int y = (int) ((dimension.getHeight() - getHeight()) / 2);
	    setLocation(x, y);

		JPanel contentPane = new JPanel();
		contentPane.setLayout(new BorderLayout());
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setBackground(Color.DARK_GRAY);
		setContentPane(contentPane);

		tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		tabbedPane.setBackground(Color.DARK_GRAY);
		contentPane.add(tabbedPane, BorderLayout.CENTER);

		listModel = new DefaultListModel<>();
		listOfUsers = new JList<>(listModel);
		listOfUsers.setBackground(Color.DARK_GRAY);
		listOfUsers.setBounds(422, 10, 197, 283);
		listOfUsers.setForeground(Color.LIGHT_GRAY);

		JScrollPane listScrollPane = new JScrollPane(listOfUsers);
		listScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		listScrollPane.setBackground(Color.DARK_GRAY);

		TitledBorder rend = BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.ORANGE), "Users");
		rend.setTitleColor(Color.ORANGE);
		rend.setTitleJustification(TitledBorder.CENTER);
		listScrollPane.setBackground(Color.DARK_GRAY);
		listScrollPane.setBorder(rend);
		listScrollPane.setPreferredSize(new Dimension(200, 0));
		contentPane.add(listScrollPane, BorderLayout.EAST);

		listOfUsers.addMouseListener(new MouseAdapter()
		{
			public void mouseClicked(MouseEvent evt)
			{
				if (evt.getClickCount() == 2 && !listOfUsers.isSelectionEmpty())
				{
					if (tabbedPane.indexOfTab(listOfUsers.getSelectedValue()) == -1)
					{
						JPanel panel = generatePanelForTab();
						tabbedPane.addTab(listOfUsers.getSelectedValue(), panel);
						tabbedPane.setSelectedIndex(tabbedPane.indexOfTab(listOfUsers.getSelectedValue()));
						networkingThread.initializeCommunication(listOfUsers.getSelectedValue());
					}
				}
			}
		});
		tabbedPane.addMouseListener(new MouseAdapter()
		{
			public void mouseClicked(MouseEvent evt)
			{
				if (evt.getButton() == MouseEvent.BUTTON2)
				{
					Component selected = tabbedPane.getSelectedComponent();
					if (selected != null)
					{
						networkingThread.destroyingCommunication(tabbedPane.getTitleAt(tabbedPane.getSelectedIndex()));

						removeTabAndReferences(tabbedPane.getTitleAt(tabbedPane.getSelectedIndex()));
					}
				}
			}
		});
	}

	/** 
	 * Removing given tab by title 
	 * @param tabName table title that need to be destroyed
	 */
	public void removeTabAndReferences(String tabName)
	{
		handlers.remove(tabbedPane.indexOfTab(tabName));
		tabbedPane.remove(tabbedPane.indexOfTab(tabName));
	}

	/**
	 * Initialize panel inside tab (creating sending button with action listener,
	 * textArea to send message and textPane for receiving messages)
	 * @return initialized panel for tab
	 */
	public JPanel generatePanelForTab()
	{
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBackground(SystemColor.inactiveCaptionBorder);

		JTextArea chatArea = new JTextArea();
		((DefaultCaret) chatArea.getCaret()).setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
		chatArea.setEditable(false);
		chatArea.setLineWrap(true);
		handlers.put(tabbedPane.getTabCount(), chatArea);
		JScrollPane jspForChat = new JScrollPane(chatArea);
		jspForChat.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		jspForChat.setBorder(BorderFactory.createTitledBorder("Conversation"));
		panel.add(jspForChat, BorderLayout.CENTER);

		JPanel outputPanel = new JPanel(new BorderLayout());
		JTextField outputTextField = new JTextField();
		outputPanel.add(outputTextField, BorderLayout.CENTER);
		JButton sendBtn = new JButton("SEND");
		outputPanel.add(sendBtn, BorderLayout.EAST);
		panel.add(outputPanel, BorderLayout.SOUTH);

		sendBtn.addActionListener(new ActionListener()
		{
			public void actionPerformed(ActionEvent arg0)
			{
				try
				{
					networkingThread.encryptAndSendMessage(tabbedPane.getTitleAt(tabbedPane.getSelectedIndex()),
							outputTextField.getText());

					chatArea.append("[" + clientName + "]" + " : " + outputTextField.getText() + "\n");
					outputTextField.setText("");
				}
				catch (IOException e)
				{
					JOptionPane.showMessageDialog(ChatClient.this, "Sending Failed", "ERROR",
							JOptionPane.ERROR_MESSAGE);
				}
			}
		});
		outputTextField.addKeyListener(new KeyAdapter()
		{
			public void keyPressed(KeyEvent e) 
			{
				if (e.getKeyCode() == KeyEvent.VK_ENTER) 
				{
					sendBtn.doClick();
				}
			}
		});

		return panel;
	}

	/**
	 * Showing message in tab with "from" title 
	 * @param userFrom nickname of user that send message
	 * @param message received message
	 * @param manInTheMiddle true- Elgamal signature is wrong
	 */
	public void showMessage(String userFrom, String message, boolean manInTheMiddle)
	{
		if (manInTheMiddle)
			handlers.get(tabbedPane.indexOfTab(userFrom))
					.append("[" + userFrom + "(ManInTheMiddle)]" + " : " + message + "\n");
		else
			handlers.get(tabbedPane.indexOfTab(userFrom)).append("[" + userFrom + "]" + " : " + message + "\n");
		tabbedPane.setSelectedIndex(tabbedPane.indexOfTab(userFrom));
	}
	
	public void showEncryptionInfo(String userFrom, String info, String msg)
	{
		handlers.get(tabbedPane.indexOfTab(userFrom)).append("[" + userFrom + "]" + " : " + info + "\n" + msg + "\n");
		tabbedPane.setSelectedIndex(tabbedPane.indexOfTab(userFrom));
	}

	// GETTERS 
	public JTabbedPane getTabbedPane()
	{
		return tabbedPane;
	}

	public DefaultListModel<String> getListModel()
	{
		return listModel;
	}
}
