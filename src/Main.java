import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.network.Ip4;

public class Main {

    public static void main(String[] args) {

        /*
         * Find and list all NICs
         */

        List<PcapIf> allDevices = new ArrayList<>(); // Will be filled with NICs
        StringBuilder errorBuffer = new StringBuilder(); // For any error messages
        int r = Pcap.findAllDevs(allDevices, errorBuffer);
        if (r == Pcap.NOT_OK || allDevices.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s",
                    errorBuffer.toString());
            return;
        }
        System.out.println("Network devices found:");
        int i = 0;
        for (PcapIf device : allDevices) {
            String description = (device.getDescription() != null) ? device
                    .getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(),
                    description);
        }

        /*
         * Ask user to choose a NIC
         */

        System.out.println("Select your network device.");
        Scanner sc = new Scanner(System.in);
        int devicenumber = 0;
        while (true) {
            try {
                devicenumber = sc.nextInt();
                if(0 <= devicenumber && devicenumber <= i)
                    break;
                System.out.println("Wrong input! Enter Another Number.");
            } catch (InputMismatchException ex) {
                System.out.println("Wrong input! Enter Another Number.");
                sc.next();
            }
        }

        /*
         * Find IP of the selected NIC
         */

        PcapIf device = allDevices.get(devicenumber);
        String deviceIP = device.getAddresses().get(0).getAddr().toString()
                .substring(7, device.getAddresses().get(0).getAddr().toString().length() - 1);
        System.out.println("Selected device IP address is: " + deviceIP);

        /*
         * Init packet capture on the selected NIC
         */

        int snaplen = 64 * 1024;
        int flags = Pcap.MODE_PROMISCUOUS;
        int timeout = 30 * 1000;
        Pcap pcap =
                Pcap.openLive(device.getName(), snaplen, flags, timeout, errorBuffer);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errorBuffer.toString());
            return;
        }

        /*
         * Ask user to specify the number of packets to capture.
         */

        int numberOfPackets = 0;
        System.out.println("Enter number of packets you want to capture.(Less than 100000)");
        while (true) {
            try {
                numberOfPackets = sc.nextInt();
                if (0 < numberOfPackets && numberOfPackets <= 100000)
                    break;
                System.out.println("Wrong input! Enter Another Number.");
            } catch (InputMismatchException ex) {
                System.out.println("Wrong input! Enter Another Number.");
                sc.next();
            }
        }

        /*
         * Start capturing packets
         */

        PcapPacket pac = new PcapPacket(JPacket.POINTER);
        Vector<PacketFlow> capturedpac = new Vector<>(numberOfPackets);
        PacketFlow rp;

        System.out.println("Capturing " + numberOfPackets + " packets:");
        int j = 0;
        while (j < numberOfPackets) {
            if (pcap.nextEx(pac) == Pcap.NEXT_EX_OK) {
                if (pac.hasHeader(new Ip4())) {
                    rp = new PacketFlow(pac, deviceIP);
                    capturedpac.addElement(rp);
                    j++;
                    if(j % 100 == 0)
                        System.out.println("Captured packet number " + j + ".");
                }
            }
        }

        /*
         * Process captured packets, aggregate the simple extracted PacketFlows into complete flows.
         */

        List<PacketFlow> resultList = new ArrayList<>();
        for (PacketFlow packetFlow : capturedpac) {
            if (resultList.contains(packetFlow)) {

                PacketFlow packetInList = resultList.get(resultList.indexOf(packetFlow));

                packetInList.setMinTime(Math.min(packetInList.getMinTime(), packetFlow.getMinTime()));
                packetInList.setMaxTime(Math.max(packetInList.getMaxTime(), packetFlow.getMaxTime()));

                packetInList.setIncomingIpHeaderSize(packetInList.getIncomingIpHeaderSize()
                        + packetFlow.getIncomingIpHeaderSize());
                packetInList.setOutgoingIpHeaderSize(packetInList.getOutgoingIpHeaderSize()
                        + packetFlow.getOutgoingIpHeaderSize());

                packetInList.setIncomingTransportHeaderSize(packetInList.getIncomingTransportHeaderSize()
                        + packetFlow.getIncomingTransportHeaderSize());
                packetInList.setOutgoingTransportHeaderSize(packetInList.getOutgoingTransportHeaderSize()
                        + packetFlow.getOutgoingTransportHeaderSize());

                packetInList.setIncomingDataSize(packetInList.getIncomingDataSize() + packetFlow.getIncomingDataSize());
                packetInList.setOutgoingDataSize(packetInList.getOutgoingDataSize() + packetFlow.getOutgoingDataSize());
            } else {
                resultList.add(packetFlow);
            }
        }

        /*
         * Produce the desired output
         */

        int fileIndex = 1;
        File file;
        while (true) {
            file = new File("output_" + fileIndex + ".csv");
            if (!file.exists()) {
                break;
            }
            fileIndex++;
        }

        FileWriter fw = null;
        try {
            fw = new FileWriter(file.getPath());
            fw.append("SourceIP,DestinationIP,SourcePort,DestinationPort,Flow's Protocol,Duration of the Flow," +
                    "Number of Bytes Sent per Flow,Number of Bytes received per Flow," +
                    "Total Bytes used for Headers in the Forward Direction");
            fw.append("\n");

            for (PacketFlow packet : resultList) {
                try {
                    fw.append(packet.getSourceIP()).append(",").append(packet.getDestinationIP()).append(",")
                            .append(String.valueOf(packet.getSourcePort())).append(",")
                            .append(String.valueOf(packet.getDestinationPort())).append(",")
                            .append(packet.getProtocol()).append(",")
                            .append(String.valueOf(packet.getMaxTime() - packet.getMinTime())).append(",")
                            .append(String.valueOf(packet.getOutgoingDataSize())).append(",")
                            .append(String.valueOf(packet.getIncomingDataSize())).append(",")
                            .append(String.valueOf(packet.getOutgoingIpHeaderSize()
                                    + packet.getOutgoingTransportHeaderSize()));
                    fw.append("\n");
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            fw.flush();
        } catch (Exception e) {
            System.out.println(e.toString());
        } finally {
            if (fw != null) {
                try {
                    fw.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        pcap.close();
    }
}