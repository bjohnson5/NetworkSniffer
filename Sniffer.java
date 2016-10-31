import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.PcapIf;
import java.util.ArrayList;
import java.util.Date;

public class Sniffer extends Thread
{
	private static StringBuilder errbuf = new StringBuilder();
	
	private static ArrayList<PcapIf> availableDevices = new ArrayList<PcapIf>();
	private static ArrayList<JPacket> listOfPackets = new ArrayList<JPacket>();
	private int deviceIndex;
	private int recievedPacketsCount;
	private SnifferWindow sniffWindow;
	public boolean keepSniffing;
	
	public Sniffer(int deviceIndexIn, SnifferWindow sniffWindowIn)
	{
		deviceIndex = deviceIndexIn;
		sniffWindow = sniffWindowIn;
	}
	
	public static ArrayList<PcapIf> GetDevices()
	{			
		// Get the devices
		Pcap.findAllDevs(availableDevices, errbuf);
		
		// Return the available devices for this Sniffer
		return availableDevices;
	}
	
	public static ArrayList<JPacket> getListOfPackets()
	{
		// Return the list of recieved packets for this Sniffer
		return listOfPackets;
	}
	
	public void stopSniffing()
	{
		keepSniffing = false;
	}
	
	public void run()
	{
		// Set the number of received packets for this sniffer to 0
		recievedPacketsCount = 0;
		
		keepSniffing = true;
		
		// Begin reading packets in for the given device
		ReadPackets(deviceIndex);
	}
	
	public void ReadPackets(int deviceIndex)
	{
		// ---------------------------Open the first device in the list (we know it will be the active one)--------------------------
		PcapIf device = availableDevices.get(deviceIndex);
		System.out.println("Opening Device: " + device.getName());
		
        int snaplen = 64 * 1024; 
        int flags = Pcap.MODE_PROMISCUOUS; 
        int timeout = 1;
        Pcap pcap =  Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        
        // --------------------------Create the Packet Handler------------------------------------
        JPacketHandler<ArrayList<JPacket>> jpacketHandler = new JPacketHandler<ArrayList<JPacket>>()
        {
        	@Override
            public void nextPacket(JPacket packet, ArrayList<JPacket> listOfPackets)
            {              
                sniffWindow.addPacket(String.valueOf(++recievedPacketsCount), new Date(packet.getCaptureHeader().timestampInMillis()).toString(), String.valueOf(packet.getCaptureHeader().caplen()), String.valueOf(packet.getCaptureHeader().wirelen()));
            	listOfPackets.add(packet);
            }
        };

        // ------------------------------Start the receive loop--------------------------------------
        while(keepSniffing)
        {
        	pcap.dispatch(1, jpacketHandler, listOfPackets);
        }
        
        // ---------------------------------Close the device-----------------------------------------
        System.out.println("Closing Device");
        pcap.close();
	}
}