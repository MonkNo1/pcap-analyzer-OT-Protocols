# from scapy.all import rdpcap
import pyshark
from scapy.all import *
import pickle
import argparse
import time
import csv


pcapfile = "130423-1.pcapng"
pickle_file_out = "pcap_pickle.pkl"
global pkts
csvlst = []
header = ["timestamp","source","Destination","ANSI","DATA"]
csvfil = "csvout.csv"
temp = []

def outcsv(pktcsv):
    print('writting in  {}...'.format(csvfil))
    with open(csvfil, 'w',newline='') as csvfile: 
        csvwriter = csv.writer(csvfile) 
        csvwriter.writerow(header)
        csvwriter.writerows(pktcsv) 
         

def readpcap():
    strt = time.time()
    print('Opening {}...'.format(pcapfile))
    # pkts = rdpcap(pcapfile)
    pkts = pyshark.FileCapture('130423-1.pcapng',display_filter='cip')
    ends = time.time()
    print("Load time : ",(ends-strt))
    print('Writing pickle file {}...'.format(pickle_file_out), end='')
    with open(pickle_file_out, 'wb') as pickle_fd:
            pickle.dump(pkts, pickle_fd)

def analyze_packet():
    for pkt in pkts:
            cal = []
            try : 
                cal.append(pkt.sniff_timestamp)
                cal.append(pkt.ip.src)
                cal.append(pkt.ip.dst)
                try:
                    cal.append(pkt.cip.symbol)
                except:
                    cal.append(" ")
                try : 
                    cal.append(pkt.cipcls.get_field_by_showname('Data'))
                except:
                    cal.append(" ")
                temp.append(cal)
            except :
                pass
    outcsv(csvlst)
    

def readpickle():
    global pkts
    strt = time.time()
    print('Opening {}...'.format(pickle_file_out))
    with open(pickle_file_out, 'rb') as pickle_fd:
        pkts  = pickle.load(pickle_fd)
    ends = time.time()
    print("Load  time : ",(ends-strt))
    print("Pickle Load COmplete...!")
    print("Some Sample Packets...!")
    for m in range(0,10):
        print(pkts[m].summary())
    print("....")
    analyze_packet()
    
       
if __name__=="__main__":    
    parser = argparse.ArgumentParser(description ='Enter  The File name to Process')
    parser.add_argument('pkl_file',
                    metavar ='-pkl',
                    type = str,
                    nargs ='+',
                    help ='This for directly loading a Pickle file',
                    action="store_true")
    _StoreTrueAction(readpickle())
  
    parser.add_argument('Pcap_file',
                    metavar ='-pcap',
                    type = str,
                    nargs ='+',
                    help ='This for will load a Pcap file and convert it to pickle File and porcess it ...!',
                    action="store_true")
    _StoreTrueAction(readpcap())
    args = parser.parse_args()
    # file_ext = args.split(".")
    # print(file_ext)

  
    # readpickle()
