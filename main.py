from scapy.all import rdpcap
from scapy.all import *
import pickle
import time
import csv


pcapfile = "130423-1.pcapng"
pickle_file_out = "pcap_pickle.pkl"
csvfil = "csvout.csv"
global pkts
csvlst = []
header = ["soruce","Destination","protocal","data","timestamp"]

def outcsv(pktcsv):
    print('writting in  {}...'.format(csvfil))
    with open(csvfil, 'w',newline='') as csvfile: 
        csvwriter = csv.writer(csvfile) 
        csvwriter.writerow(header)
        csvwriter.writerows(pktcsv) 
         

def readpcap():
    strt = time.time()
    print('Opening {}...'.format(pcapfile))
    pkts = rdpcap(pcapfile)
    ends = time.time()
    print("Load time : ",(ends-strt))
    print('Writing pickle file {}...'.format(pickle_file_out), end='')
    with open(pickle_file_out, 'wb') as pickle_fd:
            pickle.dump(pkts, pickle_fd)

def analyze_packet():
    for pkt in pkts:
        if TCP in pkt and Raw in pkt:
            try :
                if "HMI" in str(pkt[Raw].load): #Finds The  packets with contains HMI
                    # print(pkt[Raw].load)
                    src = str(pkt[IP].src)
                    dst = str(pkt[IP].dst)
                    prot= "cip"
                    data =str(pkt[Raw].load)
                    timest = str(pkt.time)
                    val = [src,dst,prot,data,timest]
                    # print("Packet : ", val)
                    csvlst.append(val)
            except :
                pass
        else : 
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
    
        
readpickle()
