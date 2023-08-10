# PCAP-Filter
The provided Python script offers a distinctive approach to packet analysis compared to Wireshark. In Wireshark, captured packets are typically saved in pcap files. However, this script diverges by enabling users to filter packets within a pcap file using custom-defined filters, and rather than storing these filtered packets in local files, it facilitates storage within a MySQL server.

To employ this script effectively, users must configure and modify server credentials within the script itself. This configuration empowers users to seamlessly connect to a MySQL server of their choice, facilitating efficient and organized storage of the filtered packet data.

This approach delivers several benefits. It allows for centralized and structured storage of packet data, enhancing accessibility and collaboration among team members. Furthermore, utilizing a database system like MySQL enables users to perform complex queries and analyses on the captured packets, providing deeper insights into network traffic patterns and potential security vulnerabilities.

In summary, this Python script not only streamlines the process of filtering and storing packets from a pcap file but also distinguishes itself by leveraging the power of a MySQL server for data management, thereby offering a unique and flexible solution for network packet analysis.
