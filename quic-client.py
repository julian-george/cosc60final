from scapy.all import *

def main():
    p = IP("192.168.64.8") / UDP(sport=10930, dport=443)
    sr(p)


if __name__ == "__main__":
    main()
