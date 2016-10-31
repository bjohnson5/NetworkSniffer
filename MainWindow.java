import java.awt.EventQueue;
import javax.swing.JFrame;
import javax.swing.JPanel;
import java.awt.FlowLayout;
import javax.swing.JLabel;
import java.awt.BorderLayout;
import javax.swing.JList;
import javax.swing.AbstractListModel;
import javax.swing.border.TitledBorder;

import org.jnetpcap.PcapIf;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JTextField;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.awt.event.ActionEvent;
import javax.swing.SwingConstants;
import java.awt.GridLayout;

public class MainWindow {

	private JFrame frame;
	private Sniffer sniff;
	private boolean sniffing;
	private SnifferWindow sniffWin;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					MainWindow window = new MainWindow();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public MainWindow() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		
		// Create and add components to the main window
		frame = new JFrame();
		frame.setBounds(100, 100, 861, 481);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(new BorderLayout(0, 0));
		
		JPanel panel = new JPanel();
		frame.getContentPane().add(panel, BorderLayout.NORTH);
		panel.setLayout(new GridLayout(0, 1, 0, 0));
		
		JLabel lblWelcomeToNetworksniffer = new JLabel("Welcome to NetworkSniffer");
		lblWelcomeToNetworksniffer.setHorizontalAlignment(SwingConstants.CENTER);
		panel.add(lblWelcomeToNetworksniffer);
		
		JButton btnStartSniffing = new JButton("Start Sniffing");
		panel.add(btnStartSniffing);
		
		JButton btnStopSniffing = new JButton("Stop Sniffing");
		panel.add(btnStopSniffing);
		
		JPanel panel_3 = new JPanel();
		frame.getContentPane().add(panel_3, BorderLayout.CENTER);
		panel_3.setLayout(new GridLayout(0, 2, 0, 0));
		
		JPanel panel_1 = new JPanel();
		panel_3.add(panel_1);
		panel_1.setBorder(new TitledBorder(null, "Choose a Connection", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		panel_1.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
		
		JList<String> list = new JList<String>();
		panel_1.add(list);
		
		JPanel panel_2 = new JPanel();
		panel_3.add(panel_2);
		panel_2.setBorder(new TitledBorder(null, "Apply a Filter", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		panel_2.setLayout(null);
		
		JLabel lblProtocol = new JLabel("Protocol:");
		lblProtocol.setBounds(18, 18, 51, 16);
		panel_2.add(lblProtocol);
		
		JCheckBox chckbxUdp = new JCheckBox("UDP");
		chckbxUdp.setBounds(18, 34, 49, 25);
		panel_2.add(chckbxUdp);
		
		JCheckBox chckbxTcp = new JCheckBox("TCP");
		chckbxTcp.setBounds(18, 59, 49, 25);
		panel_2.add(chckbxTcp);
		
		JLabel lblSourcePort = new JLabel("Source Port:");
		lblSourcePort.setBounds(18, 93, 72, 16);
		panel_2.add(lblSourcePort);
		
		JTextField textField;
		textField = new JTextField();
		textField.setBounds(6, 113, 410, 30);
		panel_2.add(textField);
		textField.setColumns(1);
		
		JLabel lblSourceAddress = new JLabel("Source Address:");
		lblSourceAddress.setBounds(18, 159, 95, 16);
		panel_2.add(lblSourceAddress);
		
		JTextField textField_1;
		textField_1 = new JTextField();
		textField_1.setBounds(6, 178, 410, 30);
		panel_2.add(textField_1);
		textField_1.setColumns(1);
		
		// Get the available devices and add them to the list
		ArrayList<PcapIf> devices = Sniffer.GetDevices();
		list.setModel(new AbstractListModel<String>() {
			/**
			 * 
			 */
			private static final long serialVersionUID = 1L;
			public int getSize() {
				return devices.size();
			}
			public String getElementAt(int index) {
				return devices.get(index).getName();
			}
		});
		
		// Set the starting value of sniffing to false and set up the event listeners for the two buttons
		sniffing = false;
		btnStartSniffing.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				if(sniffing == false && !list.isSelectionEmpty())
				{
					sniffing = true;
					sniffWin = new SnifferWindow();
					sniff = new Sniffer(list.getSelectedIndex(), sniffWin);
					sniff.start();
				}
			}
		});
		
		btnStopSniffing.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				sniffing = false;
				sniff.stopSniffing();
				sniffWin.closeWindow();
			}
		});
	}
}
