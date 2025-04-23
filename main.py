import argparse
import logging
import re
import os
import requests
import pcapy
from impacket import ImpactDecoder
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define suspicious string patterns (can be expanded)
PATTERNS = {
    "bitcoin_address": r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
    "ethereum_address": r"0x[a-fA-F0-9]{40}",
    "zeus_config": r"Zeus.*Config", # Example, needs to be refined
    "suspicious_url": r"https?://.*(exe|dll|scr)",
    "ip_address": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" #Basic IP check, refine
}

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Extracts suspicious strings from files, PCAP captures, or web pages.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to a text file to scan.")
    group.add_argument("-p", "--pcap", help="Path to a PCAP file to scan.")
    group.add_argument("-u", "--url", help="URL of a web page to scan.")
    parser.add_argument("-o", "--output", help="Path to the output file. If not specified, prints to console.")
    return parser

def extract_strings_from_file(file_path):
    """
    Extracts suspicious strings from a given text file.

    Args:
        file_path (str): The path to the text file.

    Returns:
        dict: A dictionary where keys are the pattern names and values are lists of found strings.
    """
    results = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()
        for pattern_name, pattern in PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                results[pattern_name] = matches
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Error processing file {file_path}: {e}")
        return None
    return results

def extract_strings_from_pcap(pcap_path):
    """
    Extracts suspicious strings from a given PCAP file.

    Args:
        pcap_path (str): The path to the PCAP file.

    Returns:
        dict: A dictionary where keys are the pattern names and values are lists of found strings.
    """
    results = {}
    try:
        # Initialize the PCAP reader
        reader = pcapy.open_offline(pcap_path)
        decoder = ImpactDecoder.EthDecoder()

        while True:
            try:
                header, data = reader.next()
                ethernet = decoder.decode(data)
                ip_packet = ethernet.child()
                if ip_packet is not None:
                   payload = ip_packet.child()
                   if payload is not None:
                       payload_data = payload.get_bytes()
                       text = payload_data.decode("utf-8", errors="ignore")

                       for pattern_name, pattern in PATTERNS.items():
                           matches = re.findall(pattern, text)
                           if matches:
                               if pattern_name not in results:
                                   results[pattern_name] = []
                               results[pattern_name].extend(matches)
            except pcapy.PcapError as e:
                if "No more packets" in str(e):
                    break  # End of PCAP file
                else:
                    logging.error(f"Error reading PCAP: {e}")
                    return None
            except Exception as e:
                logging.error(f"Error processing PCAP {pcap_path}: {e}")
                return None

        # Remove duplicates
        for pattern_name, matches in results.items():
            results[pattern_name] = list(set(matches))

    except FileNotFoundError:
        logging.error(f"PCAP file not found: {pcap_path}")
        return None
    except Exception as e:
        logging.error(f"Error opening PCAP file {pcap_path}: {e}")
        return None

    return results

def extract_strings_from_url(url):
    """
    Extracts suspicious strings from a given URL.

    Args:
        url (str): The URL to scan.

    Returns:
        dict: A dictionary where keys are the pattern names and values are lists of found strings.
    """
    results = {}
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        soup = BeautifulSoup(response.content, "html.parser")
        text = soup.get_text()

        for pattern_name, pattern in PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                results[pattern_name] = matches

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL {url}: {e}")
        return None
    except Exception as e:
        logging.error(f"Error processing URL {url}: {e}")
        return None
    return results

def write_results(results, output_file):
    """
    Writes the results to a file or prints them to the console.

    Args:
        results (dict): The dictionary of results to write.
        output_file (str): The path to the output file, or None to print to console.
    """
    if not results:
        print("No suspicious strings found.")
        return

    output_string = ""
    for pattern_name, matches in results.items():
        output_string += f"--- {pattern_name} ---\n"
        for match in matches:
            output_string += f"{match}\n"
        output_string += "\n"

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output_string)
            logging.info(f"Results written to {output_file}")
        except Exception as e:
            logging.error(f"Error writing to file {output_file}: {e}")
    else:
        print(output_string)

def main():
    """
    Main function to parse arguments and call the appropriate functions.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    results = {}

    if args.file:
        results = extract_strings_from_file(args.file)
    elif args.pcap:
        results = extract_strings_from_pcap(args.pcap)
    elif args.url:
        results = extract_strings_from_url(args.url)

    if results is not None:
       write_results(results, args.output)


if __name__ == "__main__":
    main()

# Usage Examples:
#
# 1. Scan a text file:
#    python tia_suspicious_string_extractor.py -f suspicious.txt
#
# 2. Scan a PCAP file:
#    python tia_suspicious_string_extractor.py -p capture.pcap
#
# 3. Scan a URL:
#    python tia_suspicious_string_extractor.py -u http://example.com/malicious.html
#
# 4. Output results to a file:
#    python tia_suspicious_string_extractor.py -f suspicious.txt -o results.txt
#
# 5. Help menu
#   python tia_suspicious_string_extractor.py -h