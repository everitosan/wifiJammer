import argparse
from multiprocessing import Process
import signal
import random
from scapy.all  import *

def setArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i',
        '--interface',
        required=True,
        type=str,
        help=('Indicates the interface used to jamm')
    )

    return parser.parse_args()

def channel_hop(interface):
    while True:
        try:
            channel = random.randrange(1,13)
            os.system("iwconfig %s channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break

def stopHopper(signal, frame):
    global stop_sniff
    stop_sniff = True
    print("Sniff Stoped ...")
    hopper.terminate()
    hopper.join()
    print("Channel hop stopped ...")

def keep_sniffing(pckt):
    global stop_sniff
    return stop_sniff

def add_network(pckt, known_networks):
    essid = pckt[Dot11Elt].info if '\x00' not in pckt[Dot11Elt].info  and pckt[Dot11Elt].info != '' else 'Hidden SSID'
    bssid = pckt[Dot11Elt].addr3
    channel = int(ord(pckt[Dot11Elt:3].info))
    if bssid not in known_networks:
        known_networks[bssid] = (essid, channel)
        print "{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid)

if __name__ == "__main__":
    parser = setArgs()
    networks = {}
    stop_sniff = False
    print("Press CTRL+C to stop sniffing...")
    print("="*100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel', 'ESSID','BSSID') + '='*100)
    hopper = Process(target= channel_hop, args=(parser.interface,) )
    hopper.start()
    signal.signal(signal.SIGINT, stopHopper)
    sniff(lfilter = lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), stop_filter= keep_sniffing, prn = lambda x: add_network(x.networks) )
