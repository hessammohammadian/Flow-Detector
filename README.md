# Flow Detector

Flow Detector can read the traffic of a selected NIC on a machine and create the traffic flows and save them in a .csv file with 5 labels and 4 features.

# Labels
SourceIP, DestinationIP, SourcePort, DestinationPort, and Flow's Protocol

# Features
Duration of the Flow, Number of Bytes Sent per Flow, Number of Bytes received per Flow, and Total Bytes used for Headers in the Forward Direction

Since Java standard library does not provide means to capture an entire NIC, this application utilizes the jNetPcap java library which itself relies on an external native application called WinPcap (Just like Wireshark) to capture all traffic on a NIC.
