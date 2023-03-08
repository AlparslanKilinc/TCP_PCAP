import dpkt
import socket
from dpkt.compat import compat_ord
import datetime
from collections import defaultdict

# Function to get IP Address converted
def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


flows=defaultdict(list)
# Read in the File to analyze 
with open('./assignment2.pcap', 'rb') as given_file:
    pcap = dpkt.pcap.Reader(given_file)
    for ts,buf in pcap:
        eth=dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data,dpkt.ip.IP):
            ip=eth.data
        if isinstance(ip.data,dpkt.tcp.TCP):
            tcp=ip.data
# We Will Differentiate Each Flow by Their src_IP , src_Port , dst_IP , dst_Port.
        flow=(inet_to_str(ip.src),tcp.sport,inet_to_str(ip.dst),tcp.dport)
        reverse=(inet_to_str(ip.dst),tcp.dport,inet_to_str(ip.src),tcp.sport)
        # If reverse is in flows it means that this is packet is from the receiver
        if reverse in flows:
            flows[reverse].append(("Receiver",tcp.seq,tcp.ack,tcp.win,tcp,ts))
        else:
            flows[flow].append(("Sender",tcp.seq,tcp.ack,tcp.win,tcp,ts))


def get_flow_info(flows,flow_num):
    flow_info=""
    i=0
    for flow in flows:
        if i==flow_num:
            break
        flow_info=flow
        i+=1   
    return flow_info

def get_transaction(flow):
    # val is the flow arrays 
    # get the given flow_num flow array that has all the packets
    i=0
    flow_array=flows[flow]
    sender=[]
    receiver=[]
    # Return the Transaction requested which will be 1 sender , 1 receiver ACK 
    # Start from index 2 which is after 3-way handshake
    for index in range(2,len(flow_array)):
        if flow_array[index][0]=="Sender" and len(sender)<2:
            sender.append(flow_array[index])
        if flow_array[index][0]=="Receiver" and len(receiver)<2:
            receiver.append(flow_array[index])
    return [sender,receiver]

def get_throughput(flow):
    # get the flow array with each packet
    flow_array=flows[flow]
    # Get the time between first byte send to last byte. at position [-1] time stamp is stored.
    # flow_array[x] -> position in the flow 
    # flow_array[x][x] -> position in the tuple where info about the packet is stored
    start_time=flow_array[0][-1]
    time = flow_array[-1][-1] - start_time
    total=0

    for packet in flow_array:
        # tcp is stored at second last position in each packet tuple
        total+= len(packet[-2])

    return total/time

def get_cong_window(flow):
    # Congestion window size will grow with the sliding window, for each RTT-intervals. 
    # we will count the amount of acks sent that will be our cwnd in a RTT.
    # TCP sends a ACK for each packet received so, if the sender send a certain amount of ACKS before recv respond.
    # that will be the amount of the cwnd and it will grow as such until it sees a loss. 
    # if lost based congestion control is implemented.
    # We will consider the packets after the 3-way handshake.
    flow_array=flows[flow]
    cong_window=[]
    count=0
    recv=0
    data=0
    #  packet info ("Sender",tcp.seq,tcp.ack,tcp.win,tcp,ts))
    for index in range(3,len(flow_array)):
        # Sender Recv a packet 1-RTT , window has slide. cwnd reached.
        if len(cong_window)==3:
            break
        if flow_array[index][0]=="Receiver":
                    recv+=1
                    # Once all the SEQ from the sender is ACK from the receiver append the amount of bytes
                    if count==recv:
                        cong_window.append(data)
                        count=0
                        recv=0
                        data=0
        # Sender ACK
        if flow_array[index][0]=="Sender" and recv==0:
            count+=1
            data+=len(flow_array[index][-2])

    return cong_window




def get_retransmission(flow):
    retransmissions=defaultdict(list)
    # loop through the flow and find when retransmission from sender by sequence number repeat.
    num_ack=[]
    array=[]
    flow_array=flows[flow]
    for index,packet in enumerate(flow_array):
        # check sender
        #  packet info ("Sender",tcp.seq,tcp.ack,tcp.win,tcp,ts))
        if packet[0]=="Sender":
            # get sequence number and the index in the flow if we get same seq it will indicate re-transmission
            retransmissions[packet[1]].append(index)

    # For each retransmission check the range for when acks in between happened
    for seq,rang in retransmissions.items():
        # indication no retransmission 
        if(len(rang) < 2): continue
        count=0
        start, end = rang
        # Inspect the packets from when the sender sent the seq and when it retransmit again
        # the packets in between will tell us how many ack 
        # the receiver needs to send the ack that is equal to the ack we will count how many times this happens.
        # if more than or equal to 3 Triple ack less means timeout
        # if we get ack's that are different than the seq it will mean that it retransmitted for other reasons.
        for i in range(start,end+1):
            if flow_array[i][0]=="Receiver":
                if flow_array[i][2]==seq:
                    count+=1
        num_ack.append(count)
    

    triple_dup = other = timeout = 0

    for val in num_ack:
        if val<2 and val>0:
            timeout += 1
            # timeout 
        elif val>=3:
            triple_dup += 1
            # triple ack
        else:
            other += 1
            # neither
    array.append(triple_dup)
    array.append(timeout)
    array.append(other)
    return array



def print_flow(flows):
    print("Flow Count",len(flows))
    for i in range(len(flows)):
        flow=get_flow_info(flows,i+1)
        print("Source IP:" ,flow[0],"Source Port",flow[1])
        print("Destination IP:", flow[2],"Destination Port",flow[3])
        t_put=get_throughput(flow)
        print("Throughput:",t_put)
        cong_wind=get_cong_window(flow)
        print("Congestion Window:",cong_wind)
        retransmissions=get_retransmission(flow)
        print("3-ACK:",retransmissions[0],"Timeout",retransmissions[1],"Other",retransmissions[2])
        trs=get_transaction(flow)
        print("Transaction 1")
        print("Sender ->"," Sequence:",trs[0][0][1]," ACK:",trs[0][0][2]," Receive Window:",trs[0][0][3])
        print("Receiver ->"," Sequence:",trs[1][0][1]," ACK:",trs[1][0][2]," Receive Window:",trs[1][0][3])
        print("Transaction 2")
        print("Sender ->"," Sequence:",trs[0][1][1]," ACK:",trs[0][1][2]," Receive Window:",trs[0][1][3])
        print("Receiver ->"," Sequence:",trs[1][1][1]," ACK:",trs[1][1][2]," Receive Window:",trs[1][1][3])

print_flow(flows)
