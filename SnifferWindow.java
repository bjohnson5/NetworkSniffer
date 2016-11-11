import javax.swing.JFrame;
import javax.swing.JPanel;

import java.awt.BorderLayout;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.GridLayout;

public class SnifferWindow{

	private JFrame frame;
	private JTable table;

	/**
	 * Create the application.
	 */
	public SnifferWindow() {
		initialize();
		this.frame.setVisible(true);
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		
		// Create and add components to the Sniffer Window
		frame = new JFrame();
		frame.setBounds(100, 100, 1119, 659);
		frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
		frame.getContentPane().setLayout(new BorderLayout(0, 0));
		
		JPanel panel = new JPanel();
		frame.getContentPane().add(panel);
		panel.setLayout(new GridLayout(0, 1, 0, 0));
		
		JPanel container = new JPanel();
		JScrollPane scrollPane = new JScrollPane(container);
		panel.add(scrollPane);
		
		JPanel container2 = new JPanel();
		JScrollPane scrollPane2 = new JScrollPane(container2);
		panel.add(scrollPane2);
		
		table = new JTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.setModel(new DefaultTableModel(
			new Object[][] {
			},
			new String[] {
				"Packet Number", "Time", "Capture Length", "Protocol", "Source Address", "Destination Address", "Source Port", "Destination Port"
			}
		));
		table.getColumnModel().getColumn(0).setPreferredWidth(80);
		table.getColumnModel().getColumn(1).setPreferredWidth(80);
		table.getColumnModel().getColumn(2).setPreferredWidth(80);
		table.getColumnModel().getColumn(3).setPreferredWidth(80);
		table.getColumnModel().getColumn(4).setPreferredWidth(80);
		table.getColumnModel().getColumn(5).setPreferredWidth(80);
		table.getColumnModel().getColumn(6).setPreferredWidth(80);
		table.getColumnModel().getColumn(7).setPreferredWidth(80);
		container.setLayout(new BorderLayout(0, 0));
		container.add(table.getTableHeader(), BorderLayout.PAGE_START);
		container.add(table, BorderLayout.CENTER);
				
		JTextArea textArea = new JTextArea();
		container2.add(textArea);
		
		// Add an event listener for when the user selects a row of the table (a packet)
		table.getSelectionModel().addListSelectionListener(new ListSelectionListener(){
			@Override
			public void valueChanged(ListSelectionEvent arg0) {
				int selectedPacket[] = table.getSelectedRows();
				int index = selectedPacket[0];
				textArea.setText(Sniffer.getListOfPackets().get(index).toHexdump());
			}
	    });
	}
	
	public void addPacket(String num, String time, String capLen, String protocol, String source, String destination)
	{
		DefaultTableModel model = (DefaultTableModel) table.getModel();
		model.addRow(new Object[]{num, time, capLen, protocol, source, destination});
	}
	
	public void closeWindow()
	{
		frame.dispose();
	}
}
