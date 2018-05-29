
from scapy.all import *
from struct import *

ip = IP()
ip.src = '198.13.0.15' #sursa      = mid1 
ip.dst = '198.13.0.14' #destinatia = rt1
#intrebarea 1 ce reprezinta DSCP si ECN
ip.tos = int('011110' + '11', 2) #DSCP && ECN 

tcp = TCP()
tcp.sport = 54321 #port sursa
tcp.dport = 10000 #port destinatie 

#MSS este cantitatea efectiva de date
#adica litera in cazul nostru 
optiune = 'MSS' 
op_index = TCPOptions[1][optiune] 
op_format = TCPOptions[0][op_index] #!H
valoare = struct.pack(op_format[1], 2) # valoarea 2 a fost inpachetata intr-un string de 2 byte
tcp.options = [(optiune, valoare)] #['MSS',2]

#s
tcp.seq = 100

tcp.flags = 'S' #SYN
raspuns_syn_ack = sr1(ip/tcp)# se trimite un pachet ce contine ip si tcp si se asteapta un singur raspuns

tcp.seq += 1
tcp.ack = raspuns_syn_ack.seq + 1

tcp.flags = 'A' #ACK
ACK = ip / tcp
send(ACK) #se trimite pachetul fara a se astepta un raspuns
#f
#se stabileste 3 way handshake de la s=>f

cuvant='cuvant'
for x in range(0, 3):

    tcp.flags = 'PAEC'
    tcp.ack = raspuns_syn_ack.seq + 1
    ch=cuvant[x]
    #print ch
    rcv = sr1(ip/tcp/ch)
    #print rcv[1]
    tcp.seq += 1

tcp.flags='R' #R este pt reset si pur si simplu se inchide conexiunea trimitand un pachet cu flagul asta
RES = ip/tcp
send(RES)








