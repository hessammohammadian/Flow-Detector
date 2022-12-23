import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 * This class extracts the meta data from each packet to create the desired output.
 */
public class PacketFlow {

    /**
     * IP of the source peer.
     */
    private String sourceIP;

    /**
     * IP of the destination peer.
     */
    private String destinationIP;

    /**
     * Port of the source peer.
     */
    private int sourcePort;

    /**
     * Port of the destination port.
     */
    private int destinationPort;

    /**
     * Transport layer protocol.
     */
    private String protocol;

    /**
     * Start time of the traffic flow.
     */
    private long minTime;

    /**
     * End time of the traffic flow.
     */
    private long maxTime;

    /**
     * IP layer header size of incoming packets in the flow.
     */
    private int incomingIpHeaderSize;

    /**
     * Transport layer header size of incoming packets in the flow.
     */
    private int incomingTransportHeaderSize;

    /**
     * Application layer data size of incoming packets in the flow.
     */
    private int incomingDataSize;

    /**
     * IP layer header size of outgoing packets in the flow.
     */
    private int outgoingIpHeaderSize;

    /**
     * Transport layer header size of outgoing packets in the flow.
     */
    private int outgoingTransportHeaderSize;

    /**
     * Application layer data size of outgoing packets in the flow.
     */
    private int outgoingDataSize;

    /**
     * Analyzes a captured packet and creates a simple packet flow from it.
     * <p>
     * Note: Extracted packet flows will later be aggregated.
     *
     * @param pp       The captured network packet.
     * @param deviceIP IP of the current NIC to detect incoming/outgoing state.
     */
    public PacketFlow(PcapPacket pp, String deviceIP) {
        Ip4 ip = new Ip4();
        Tcp tcp = new Tcp();
        Udp udp = new Udp();
        pp.hasHeader(ip);
        this.sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(ip.source());
        this.destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(ip.destination());

        this.minTime = pp.getCaptureHeader().timestampInMillis();
        this.maxTime = pp.getCaptureHeader().timestampInMillis();

        boolean outgoing = this.sourceIP.equals(deviceIP);

        if (outgoing) {
            this.incomingIpHeaderSize = 0;
            this.outgoingIpHeaderSize = ip.size();
        } else {
            this.incomingIpHeaderSize = ip.size();
            this.outgoingIpHeaderSize = 0;
        }

        if (pp.hasHeader(tcp)) {
            this.sourcePort = tcp.source();
            this.destinationPort = tcp.destination();
            this.protocol = "TCP";
            if (outgoing) {
                this.incomingTransportHeaderSize = 0;
                this.outgoingTransportHeaderSize = tcp.size();
            } else {
                this.incomingTransportHeaderSize = tcp.size();
                this.outgoingTransportHeaderSize = 0;
            }
        }

        if (pp.hasHeader(udp)) {
            this.sourcePort = udp.source();
            this.destinationPort = udp.destination();
            this.protocol = "UDP";
            if (outgoing) {
                this.incomingTransportHeaderSize = 0;
                this.outgoingTransportHeaderSize = udp.size();
            } else {
                this.incomingTransportHeaderSize = udp.size();
                this.outgoingTransportHeaderSize = 0;
            }
        }

        if (outgoing) {
            this.incomingDataSize = 0;
            this.outgoingDataSize = pp.size() - outgoingIpHeaderSize - outgoingTransportHeaderSize;
        } else {
            this.incomingDataSize = pp.size() - incomingIpHeaderSize - incomingTransportHeaderSize;
            this.outgoingIpHeaderSize = 0;
        }
    }

    //region Getters and Setters

    public String getSourceIP() {
        return sourceIP;
    }

    public String getDestinationIP() {
        return destinationIP;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public long getMinTime() {
        return minTime;
    }

    public void setMinTime(long minTime) {
        this.minTime = minTime;
    }

    public long getMaxTime() {
        return maxTime;
    }

    public void setMaxTime(long maxTime) {
        this.maxTime = maxTime;
    }

    public int getIncomingIpHeaderSize() {
        return incomingIpHeaderSize;
    }

    public void setIncomingIpHeaderSize(int incomingIpHeaderSize) {
        this.incomingIpHeaderSize = incomingIpHeaderSize;
    }

    public int getIncomingTransportHeaderSize() {
        return incomingTransportHeaderSize;
    }

    public void setIncomingTransportHeaderSize(int incomingTransportHeaderSize) {
        this.incomingTransportHeaderSize = incomingTransportHeaderSize;
    }

    public int getIncomingDataSize() {
        return incomingDataSize;
    }

    public void setIncomingDataSize(int incomingDataSize) {
        this.incomingDataSize = incomingDataSize;
    }

    public int getOutgoingIpHeaderSize() {
        return outgoingIpHeaderSize;
    }

    public void setOutgoingIpHeaderSize(int outgoingIpHeaderSize) {
        this.outgoingIpHeaderSize = outgoingIpHeaderSize;
    }

    public int getOutgoingTransportHeaderSize() {
        return outgoingTransportHeaderSize;
    }

    public void setOutgoingTransportHeaderSize(int outgoingTransportHeaderSize) {
        this.outgoingTransportHeaderSize = outgoingTransportHeaderSize;
    }

    public int getOutgoingDataSize() {
        return outgoingDataSize;
    }

    public void setOutgoingDataSize(int outgoingDataSize) {
        this.outgoingDataSize = outgoingDataSize;
    }
    //endregion

    /**
     * Compares two flow objects and returns true if they are considered to be one flow.
     * Two PacketFlow objects are equal if they use the same protocol and if the ip:port of the peers are equal.
     * Note that it is not required that sources match each other and destinations match each other, it is sufficient
     * that the source-destination combo match each other.
     *
     * @param o The other object to check equality with.
     * @return true if equal, false otherwise.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PacketFlow that = (PacketFlow) o;

        if (!protocol.equals(that.protocol)) {
            return false;
        }

        if (sourcePort == that.sourcePort &&
                destinationPort == that.destinationPort &&
                sourceIP.equals(that.sourceIP) &&
                destinationIP.equals(that.destinationIP)) {
            return true;
        }

        if (sourcePort == that.destinationPort &&
                destinationPort == that.sourcePort &&
                sourceIP.equals(that.destinationIP) &&
                destinationIP.equals(that.sourceIP)) {
            return true;
        }
        return false;
    }
}
