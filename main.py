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
    with open(csvfil, 'w') as csvfile: 
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


# for k in range(0,10):
#     timestamp =  pkts[k].time
#     print(timestamp)


# a002b3a
# 20200020013000000

# b'00260078060b000000000000000000000000000000000000000000000002005c78613100040075425c7863665c7866665c78623100120025045c7863630000005c786130025c7862335c786
# 1320200020013000000'
# b'7000260078060b000000000000000000000000000000000000000000000002005c786131000400654c5c7863665c7866665c7862310012005c786661095c7863630000005c786130025c7862335c786
# 1320200020013000000'
# 'p\x00\x1a\x00\x01\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\\xa1\x00\x04\x00\\xaal\\x80\\xff\\xb1\x00\x06\x00~M\\xcd\x00\x00\x00'

# 'p\x00\x1a\x00\x01\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\\xa1\x00\x04\x00\\xaal\\x80\\xff\\xb1\x00\x06\x00}M\\xcd\x00\x00\x00
