import argparse
from multiprocessing import Process
import signal
import random

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
    #channel_hop.terminate()
    #channel_hop.join()
    print("Channel hop stopped ...")

if __name__ == "__main__":
    parser = setArgs()
    networks = {}
    stop_sniff = False
    print("Press CTRL+C to stop sniffing...")
    print("="*100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel', 'ESSID','BSSID') + '='*100)
    hopper = Process(target= channel_hop, args=(parser.interface,) )
    #hopper.start()
    signal.signal(signal.SIGINT, stopHopper)
    while not stop_sniff:
        channel = random.randrange(1,13)
