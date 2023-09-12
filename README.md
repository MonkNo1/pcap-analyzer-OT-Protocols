# PCAP to CSV Converter with Packet Analysis

## Description
The PCAP to CSV Converter is a Python script designed to streamline the analysis of network traffic data captured in PCAP (Packet Capture) files, especially in industrial and automation environments. This versatile tool leverages the Scapy library to parse PCAP files, identify specific network packets containing Human Machine Interface (HMI) data, and then store relevant information in a CSV (Comma-Separated Values) file for further analysis and visualization.

## Features
- **Efficient PCAP to Pickle Conversion**: The script allows you to convert PCAP files (`pcapfile`) into binary pickle files (`pickle_file_out`). This conversion process enhances efficiency by enabling fast loading of PCAP data for subsequent analysis.

- **Packet Analysis**: The script thoroughly inspects each packet within the PCAP file, focusing on TCP packets with raw data payloads. It specifically searches for packets that contain the string "HMI," signifying Human Machine Interface data. Extracted packet data includes source IP addresses, destination IP addresses, protocols, raw payload content, and timestamps.

- **Structured CSV Output**: The extracted packet data is systematically organized and stored in a CSV file (`csvfil`). The CSV file includes a header row for clarity, making it suitable for direct analysis and visualization.

- **Command-Line Flexibility**: The script is equipped with command-line arguments, providing users with the flexibility to specify their preferred input source. You can choose to process either a PCAP file (`-cap`) or a pre-converted pickle file (`-pkl`) based on your requirements.

## Usage
1. **Converting PCAP to Pickle**:
   - To process a PCAP file and generate a pickle file for efficient storage and analysis, use the following command:
     ```shell
     python pcap_to_csv_converter.py -cap 130423-1.pcapng
     ```

2. **Analyzing Pre-Converted Pickle File**:
   - If you already have a pickle file, you can analyze its contents using the following command:
     ```shell
     python pcap_to_csv_converter.py -pkl pcap_pickle.pkl
     ```

## Dependencies
To run the PCAP to CSV Converter, you must have the following dependencies installed:

- **Scapy**: The script relies on the Scapy library for packet manipulation and PCAP file reading.
- **argparse**: Used for parsing command-line arguments.
- **pickle**: Utilized for serializing and deserializing Python objects (used for storing and loading packets).
- **time**: Employed to measure the execution time of specific operations.
- **csv**: Required for reading and writing CSV files.

## Author
This PCAP to CSV Converter script with packet analysis was developed by [Your Name]. 

## License
[Specify the license under which this code is distributed, e.g., MIT License]

## Contributions
Contributions and enhancements to this script are welcome. We encourage you to fork the repository and submit pull requests to improve its functionality and usability.

## GitHub Repository
You can find the source code and further information in the [GitHub repository](https://github.com/yourusername/pcap-to-csv-converter).

## Disclaimer
Please note that this script is provided as-is. While it is a valuable tool for many scenarios, it may have limitations in handling specific PCAP formats or edge cases. Users are encouraged to test and adapt it to their specific use cases.
