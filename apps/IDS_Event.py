
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this         #
# file to you under the following license.                                     #
#                                                                              #
# Redistribution and use in source and binary forms, with or without           #
# modification, are permitted provided the following conditions are met:       #
# - Redistributions of source code must retain the above copyright             #
#   notice, this list of conditions and the following disclaimer.              #
# - Redistributions in binary form must reproduce the above copyright          #
#   notice, this list of conditions and the following disclaimer in            #
#   the documentation or other materials provided with the distribution.       #
# - The names of the copyright holds and contributors may not be used to       #
#   endorse or promote products derived from this work without specific        #
#   prior written permission.                                                  #
#                                                                              #
# Unless required by applicable law or agreed to in writing, software          #
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT    #
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the     #
# LICENSE file distributed with this work for specific language governing      #
# permissions and limitations under the License.                               #
################################################################################

################################################################################
# SETUP                                                                        #
# -------------------------------------------------------------------          #
# mininet: mininet.sh (or other single subnet network)                         #
# test:    packet contents will be printed for each packet sent                #
#          to generate a packets with a payload try                            #
#          h1 hping3 -c 10 -d 100 -E ~/pyretic/mininet/test_payload.txt -S h2  #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
import socket
import json
import re

def analisis():
    #Deteccion de un escaneo por ping con nmap
    #Caracteristicas del paquete: ethtype = 2048, header_len = 14, payload_len = 40, protocol = 6,
    #tcp_header_len = 20, tcp payload = 0
    generar_evento()
    enviar_evento()

def generar_evento():
    # Se construye el payload del evento
    message_payload= dict(inport=None,    \
                          srcmac=src_mac, \
                          dstmac=None,    \
                          srcip=src_ip,   \
                          dstip=None,     \
                          tos=None,       \
                          srcport=None,   \
                          dstport=None,   \
                          ethtype=None,   \
                          protocol=None,  \
                          vlan_id=None,   \
                          vlan_pcp=None)  \
        
def enviar_evento():
    # Se define el valor del estado al cual va a pasar el host atacado
    message_value = 'infected'
    
    # Se define que el mensaje corresponde a un estado del evento IDS
    message_type = MESSAGE_TYPES['state']
    
    # Se construye el mensaje JSON para ser enviado
    json_message = dict(event=dict(event_type='ids',                             \
                                   sender=dict(sender_id=1,                      \
                                               description=1,                    \
                                               addraddr='127.0.0.1',               \
                                               port='50002'),                      \
                                   message=dict(message_type=message_type,       \
                                               message_payload=message_payload,  \
                                               message_value=message_value),     \
                                   transition=dict(prev=1,                       \
                                               next=1)                           \
                                   ))
                                   
    # Se crea el socket a traves del cual se va a enviar el mensaje JSON
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Se conecta con el servidor para enviar el mensaje
    s.connect((options.addr, int(options.port)))
    bufsize = len(json_message)

    # Se envian los datos
    totalsent = 0
    s.sendall(json.dumps(json_message))
 
    # Receive return value
    recvdata = s.recv(1024)
    print recvdata

    # Se cierra el socket
    s.close()

def filtro(pkt):
    src_ip = pkt['srcip']
    src_mac = pkt['srcmac']
    dst_ip = pkt['dstip']
    dst_mac = pkt['dstmac']
    ethtype = pkt['ethtype']
    encabezado = pkt['header_len']
    payload = pkt['payload_len']
    if pkt['ethtype'] == 0x800:
        raw_bytes = [ord(c) for c in pkt['raw']]  
        eth_payload_bytes = raw_bytes[pkt['header_len']:]
        ip_version = (eth_payload_bytes[0] & 0b11110000) >> 4
        ihl = (eth_payload_bytes[0] & 0b00001111)
        ip_header_len = ihl * 4
        ip_payload_bytes = eth_payload_bytes[ip_header_len:]
        ip_proto = eth_payload_bytes[9]
        if ip_proto == 0x06:
            tcp_data_offset = (ip_payload_bytes[12] & 0b11110000) >> 4
            tcp_header_len = tcp_data_offset * 4
            tcp_payload_bytes = ip_payload_bytes[tcp_header_len:]
            if len(tcp_payload_bytes) > 0:
                contenido_tcp = ''.join([chr(d) for d in tcp_payload_bytes])
        elif ip_proto == 0x11:
            udp_header_len = 8
            udp_payload_bytes = ip_payload_bytes[udp_header_len:]
            if len(udp_payload_bytes) > 0:
                contenido_udp = ''.join([chr(d) for d in udp_payload_bytes])
        elif ip_proto == 0x01:
            print "ICMP packet"
        else:
            print "Unhandled packet type"
    
    analisis()
    

def capturar_paquetes():
  q = packets()
  q.register_callback(printer)
  return q

### Main ###

def main():
    return capturar_paquetes() + flood()

