# tia-SuspiciousStringExtractor
A command-line tool that scans text files, network traffic captures (PCAP files), or web pages for strings that are commonly associated with malicious activity, such as cryptocurrency addresses (Bitcoin, Ethereum), known malware configuration strings (e.g., Zeus), or URLs with suspicious patterns. Output the locations and types of suspicious strings found. - Focused on Aggregates threat intelligence feeds from various sources (e.g., MISP, OTX, Twitter) and correlates indicators of compromise (IOCs) based on customizable rules. Provides a centralized view of potential threats.

## Install
`git clone https://github.com/ShadowGuard-AI/tia-suspiciousstringextractor`

The PCAP libraries (pcapy and impacket) are only needed for `-p` scans. Text file and URL scans run without them. A PCAP scan attempted without them exits non-zero with a message naming the missing packages.

## Usage
`python main.py (-f <file> | -p <pcap> | -u <url>) [-o <output>]`

Each match is printed with its location: the source name plus a line number and character offset for file and URL scans, or a packet number and offset for PCAP scans. A failed scan, and a failed write of the `-o` output file, each exit non-zero.

## Parameters
- `-h`: Show help message and exit
- `-f`: Path to a text file to scan.
- `-p`: Path to a PCAP file to scan.
- `-u`: URL of a web page to scan.
- `-o`: Path to the output file. If not specified, prints to console.

## License
Copyright (c) ShadowGuard-AI
