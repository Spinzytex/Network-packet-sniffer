# Network-packet-sniffer
Creating a detailed `README.md` for your GitHub repository is crucial as it serves as the entry point and guide for anyone who visits your project. Here’s a sample `README.md` that you can use for your network packet sniffer project:

---

# Network Packet Sniffer

## Project Description
The Network Packet Sniffer is a Python-based tool designed to capture and analyze network traffic to detect unencrypted transmission of credentials (usernames and passwords) over insecure protocols like HTTP, FTP, and Telnet. This project aims to educate on network security practices, demonstrate the importance of encryption, and provide a practical tool for identifying potential vulnerabilities.

## Features
- Capture network packets in real-time.
- Analyze protocols such as HTTP, FTP, and Telnet.
- Detect and log unencrypted credentials.
- Provide insights into encrypted vs. unencrypted traffic.
- User-friendly logs that indicate the security status of each packet.

## Installation

### Prerequisites
- Python 3.x
- `pyshark` library

### Setup
To set up this project on your local machine, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-packet-sniffer.git
   ```
2. Navigate to the cloned directory:
   ```bash
   cd network-packet-sniffer
   ```
3. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
To run the packet sniffer, execute the following command in the terminal:
```bash
sudo python3 packet_sniffer.py
```
Make sure to run the script with `sudo` as it requires administrative privileges to capture network packets.

### Example Output
```
Captured TCP packet from 192.164:49 to192.168.1.1:00, Encrypted: No
>>> Credentials Detected! <<<
Usernames: ['admin'], Passwords: ['password123']
```

## Contributing
Contributions to this project are welcome! Please adhere to the following steps to contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes and commit them (`git commit -am 'Add some feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a new Pull Request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- SpinzyTech for initiating and maintaining this project.
- Contributors and reviewers who participate in project improvements.

--
