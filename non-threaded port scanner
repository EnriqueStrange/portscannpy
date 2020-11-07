#python non-threaded port-scanner.py
#Author: P(codename- STRANGE)
#date: 10/09/2020

import argparse, socket

def connection_scan(target_ip, target_port):
    """Attempts to create a socket connection with the given ip address and port.
    If successfull, the port is open. if not the port is closed
    """
    try:
        conn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create a socket
        conn_socket.connect((target_ip, target_port)) # connect to the socket created
        print("[+] {}/tcp open".format(target_port)) 
    except OSError:
        print("[-] {}/tcp closed".format(target_port))
    finally:
        conn_socket.close()  # ensure the connection is closed

def port_scan(target, port_num):
    """Scan indicated port for status.

    First, it attempts to resolve the ip if a provides hostname, then enumerates through the ports.
    """
    try:
        target_ip = socket.gethostbyname(target)
        print('[*] Scan results for: {}'.format(target_ip))
        connection_scan(target_ip, int(port_num))
    except OSError:
        print("[^] Cannot resolve {}: Unknown host". format(target))
        return  # Exit scan if target IP is not resolved

def argument_parser():
    """Allow target to specify target host and port"""
    parser = argparse.ArgumentParser(description = "TCP port scanner. accept a hostname/IP address and list of ports to"
                                     "scan. Attenpts to identify the service running on a port.")
    parser.add_argument("-o", "--host", nargs = "?", help = "Host IP address")
    parser.add_argument("-p", "--ports", nargs="?", help = "comma-separation port list, such as '25,80,8080'")

    var_args = vars(parser.parse_args()) # Convert argument name space to dictionary
    return var_args

if __name__ == '__main__':
    try:
        user_args = argument_parser()
        host = user_args["host"]
        port_list = user_args["ports"].split(",") # Make a list from port numbers
        for port in port_list:
            port_scan(host, port)
    except AttributeError:
        print("Error, please provide the command_line argument before running.")
