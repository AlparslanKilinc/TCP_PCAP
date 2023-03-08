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
    #that will be the amount of the cwnd and it will grow as such until it sees a loss. 
    # if lost based congestion control is implemented.

    # We will consider the packets after the 3-way handshake.
    flow_array=flows[flow]
    count=0
    cong_window=[]
    for index in range(3,len(flow_array)):
        # Sender Recv a packet 1-RTT , window has slide. cwnd reached.
        if len(cong_window)==3:
            break
        if flow_array[index][0]=="Receiver":
            cong_window.append(count)
            count=0
        # Sender ACK
        if flow_array[index][0]=="Sender":
            count+=len(flow_array[index][-2])

    return cong_window




        
        



# Flow Count 
print("Flow Count",len(flows))
# Flow 1 Information 
print("Flow 1:")
flow_1=get_flow_info(flows,1)
print("Source IP:" ,flow_1[0],"Source Port",flow_1[1])
print("Destination IP:", flow_1[2],"Destination Port",flow_1[3])
t_put=get_throughput(flow_1)
print("Throughput:",t_put)
cong_wind=get_cong_window(flow_1)
print("Congestion Window:",cong_wind)
# Transactions 
# [0] -> Sender array , [1] -> Recv array
# X[0] transaction 1 , X[1] transaction 2
# XX[0],XX[1],XX[2],... indicate tcp.seq ,tcp.ack ... for that packet
print("Transaction 1")
trs_1=get_transaction(flow_1)

print("Sender ->"," Sequence:",trs_1[0][0][1]," ACK:",trs_1[0][0][2]," Receive Window:",trs_1[0][0][3])
print("Receiver ->"," Sequence:",trs_1[1][0][1]," ACK:",trs_1[1][0][2]," Receive Window:",trs_1[1][0][3])

print("Transaction 2")
print("Sender ->"," Sequence:",trs_1[0][1][1]," ACK:",trs_1[0][1][2]," Receive Window:",trs_1[0][1][3])
print("Receiver ->"," Sequence:",trs_1[1][1][1]," ACK:",trs_1[1][1][2]," Receive Window:",trs_1[1][1][3])

# Flow 2 Information 
print("Flow 2:")
flow_2=get_flow_info(flows,2)
print("Source IP:" ,flow_2[0],"Source Port",flow_2[1])
print("Destination IP:", flow_2[2],"Destination Port",flow_2[3])
t_put=get_throughput(flow_2)
print("Throughput:",t_put)
cong_wind=get_cong_window(flow_2)
print("Congestion Window:",cong_wind)
# Transactions 
# trs_1 [0] -> Sender array  trs_1[1] -> Recv array
# trs_1 X[0] transaction 1 , trs_1 X[1] transaction 2
print("Transaction 1")
trs_2=get_transaction(flow_2)

print("Sender ->"," Sequence:",trs_2[0][0][1]," ACK:",trs_2[0][0][2]," Receive Window:",trs_2[0][0][3])
print("Receiver ->"," Sequence:",trs_2[1][0][1]," ACK:",trs_2[1][0][2]," Receive Window:",trs_2[1][0][3])

print("Transaction 2")
print("Sender ->"," Sequence:",trs_2[0][1][1]," ACK:",trs_2[0][1][2]," Receive Window:",trs_2[0][1][3])
print("Receiver ->"," Sequence:",trs_2[1][1][1]," ACK:",trs_2[1][1][2]," Receive Window:",trs_2[1][1][3])

# Flow 3 Information 
print("Flow 3:")
flow_3=get_flow_info(flows,3)
print("Source IP:" ,flow_3[0],"Source Port",flow_3[1])
print("Destination IP:", flow_3[2],"Destination Port",flow_3[3])
t_put=get_throughput(flow_3)
print("Throughput:",t_put)
cong_wind=get_cong_window(flow_3)
print("Congestion Window:",cong_wind)
# Transactions 
# trs_1 [0] -> Sender array  trs_1[1] -> Recv array
# trs_1 X[0] transaction 1 , trs_1 X[1] transaction 2
print("Transaction 1")
trs_3=get_transaction(flow_3)

print("Sender ->"," Sequence:",trs_3[0][0][1]," ACK:",trs_3[0][0][2]," Receive Window:",trs_3[0][0][3])
print("Receiver ->"," Sequence:",trs_3[1][0][1]," ACK:",trs_3[1][0][2]," Receive Window:",trs_3[1][0][3])

print("Transaction 2")
print("Sender ->"," Sequence:",trs_3[0][1][1]," ACK:",trs_3[0][1][2]," Receive Window:",trs_3[0][1][3])
print("Receiver ->"," Sequence:",trs_3[1][1][1]," ACK:",trs_3[1][1][2]," Receive Window:",trs_3[1][1][3])
