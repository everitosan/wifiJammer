import argparse
from multiprocessing import Process
import signal
import logging
from Jammer import Jammer

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
    ARGS = setArgs()

    JAMMER = Jammer(ARGS.interface)

    print("Press CTRL+C to stop sniffing...")
    print("="*100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel', 'ESSID','BSSID') + '='*100)

    HOPER = Process(target= JAMMER.start_channel_hop)
    HOPER.start()

    JAMMER.sniff()

    signal.signal(signal.SIGINT, stopHopper)

    ATTACKER = JAMMER.selectBSSID()
    ATTACKER.start()

    signal.signal(signal.SIGINT, exit)

def exit(m_signal, frame):
    JAMMER.stop_attack()
    ATTACKER.terminate()
    ATTACKER.join()

if __name__ == "__main__":
    main()
