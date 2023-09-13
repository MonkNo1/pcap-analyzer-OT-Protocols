import pyshark 
import csv

pcapfile = "130423-1.pcapng"
header = ["timestamp","source","Destination","ANSI","DATA"]
csvfil = "csvout.csv"
temp = []


def outcsv(pktcsv):
    print('writting in  {}...'.format(csvfil))
    with open(csvfil, 'a',newline='') as csvfile: 
        csvwriter = csv.writer(csvfile) 
        csvwriter.writerow(header) 
        csvwriter.writerows(pktcsv) 


       
       
if __name__=="__main__":   
    capture = pyshark.FileCapture('130423-1.pcapng',display_filter='cip')
    for pkt in capture:
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
    outcsv(temp)
