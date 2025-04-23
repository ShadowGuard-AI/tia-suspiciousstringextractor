# tia-SuspiciousStringExtractor
A command-line tool that scans text files, network traffic captures (PCAP files), or web pages for strings that are commonly associated with malicious activity, such as cryptocurrency addresses (Bitcoin, Ethereum), known malware configuration strings (e.g., Zeus), or URLs with suspicious patterns. Output the locations and types of suspicious strings found. - Focused on Aggregates threat intelligence feeds from various sources (e.g., MISP, OTX, Twitter) and correlates indicators of compromise (IOCs) based on customizable rules. Provides a centralized view of potential threats.

## Install
`git clone https://github.com/ShadowStrikeHQ/tia-suspiciousstringextractor`

## Usage
`./tia-suspiciousstringextractor [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: Path to the output file. If not specified, prints to console.

## License
Copyright (c) ShadowStrikeHQ
