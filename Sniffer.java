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
	
	public SniffedPacket ProcessPacket(JPacket packet)
	{
		SniffedPacket tempPacket = new SniffedPacket();
		tempPacket.timeStamp = new Date(packet.getCaptureHeader().timestampInMillis()).toString();
		tempPacket.length = String.valueOf(packet.getCaptureHeader().caplen());
		
		byte[] ipv4_header = new byte[20];
		byte[] ether_header = new byte[14];
		byte[] tcp_header = new byte[20];
		byte[] udp_header = new byte[8];
		
		ether_header = packet.getByteArray(0, 14);
		
		if(ether_header[12] == 0x08 && ether_header[13] == 0x00)
		{
			
			ipv4_header = packet.getByteArray(14, 20);
			if(ipv4_header[9] == 0x06)
			{
				// IPv4 -- TCP
				tempPacket.protocol = "TCP";
				tempPacket.source = String.valueOf(Byte.toUnsignedLong(ipv4_header[12])) + "." + String.valueOf(Byte.toUnsignedLong(ipv4_header[13])) + "." + String.valueOf(Byte.toUnsignedLong(ipv4_header[14])) + "." + String.valueOf(Byte.toUnsignedLong(ipv4_header[15]));
				tempPacket.destination = String.valueOf(Byte.toUnsignedLong(ipv4_header[16])) + "." + String.valueOf(Byte.toUnsignedLong(ipv4_header[17])) + "." + String.valueOf(Byte.toUnsignedLong(ipv4_header[18])) + "." + String.valueOf(Byte.toUnsignedLong(ipv4_header[19]));
				tcp_header = packet.getByteArray(34, 20);
				//TODO: Set ports
			}
			else if(ipv4_header[9] == 0x11)
			{
				tempPacket.protocol = "UDP";
				tempPacket.source = String.valueOf(Byte.toUnsignedLong(ipv4_header[12])) + "." + String.valueOf(Byte.toUnsignedLong(ipv4_header[13])) + "." + String.valueOf(Byte.toUnsignedLong(ipv4_header[14])) + "." + String.valueOf(Byte.toUnsignedLong(ipv4_header[15]));
				tempPacket.destination = String.valueOf(Byte.toUnsignedLong(ipv4_header[16])) + "." + String.valueOf(Byte.toUnsignedLong(ipv4_header[17])) + "." + String.valueOf(Byte.toUnsignedLong(ipv4_header[18])) + "." + String.valueOf(Byte.toUnsignedLong(ipv4_header[19]));
				udp_header = packet.getByteArray(34, 8);
				//TODO: Set ports
			}
		}
		else
		{
			// IPv4 -- UDP
			tempPacket.protocol = "UNKNOWN";
			tempPacket.source = "UNKNOWN";
			tempPacket.destination = "UNKNOWN";
		}
		
		return tempPacket;
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
        		SniffedPacket pkt = ProcessPacket(packet);
                sniffWindow.addPacket(String.valueOf(++recievedPacketsCount), pkt.timeStamp, pkt.length, pkt.protocol, pkt.source, pkt.destination);
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