from pyretic.lib.corelib import *
from pyretic.lib.std import *
import socket
import json
import re
from pyretic.pyresonance.globals import *

def filtro(pkt):
  
  def analizar_paquete(pkt):
    src_ip = pkt['srcip']
    src_mac = pkt['srcmac']
    dst_ip = pkt['dstip']
    dst_mac = pkt['dstmac']
    ethtype = pkt['ethtype']
    encabezado = pkt['header_len']
    payload = pkt['payload_len']
    switch = pkt['switch']
    inport = pkt['inport']
    contenido_tcp = None
    contenido_udp = None
    ip_proto = None
    tcp_header_len = None

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
    
    if contenido_tcp == None and (ip_proto == 0x11 or ip_proto == 0x06):
      analisis(src_ip, src_mac, dst_ip, dst_mac, ethtype, encabezado, payload, tcp_header_len, switch, inport)
    
  def analisis(SrcIP, SrcMAC, DstIP, DstMAC, EthType, Encabezado, Payload, TcpHeaderLen, Switch, Inport):
    
    #Deteccion de un escaneo por ping con nmap
    #Caracteristicas del paquete: ethtype = 2048, header_len = 14, payload_len = 40, protocol = 6,
    #tcp_header_len = 20, tcp payload = 0
    if EthType == 2048 and Encabezado == 14 and Payload == 40 and TcpHeaderLen == 20 and (Switch != Inport):
      generar_evento(DstMAC)

  def generar_evento(DstMAC):
    
    # Se construye el payload del evento
    message_payload= dict(inport=None,    \
			  srcmac=str(DstMAC), \
			  dstmac=None,    \
			  srcip=None,     \
			  dstip=None,     \
			  tos=None,       \
			  srcport=None,   \
			  dstport=None,   \
			  ethtype=None,   \
			  protocol=None,  \
			  vlan_id=None,   \
			  vlan_pcp=None)
    print message_payload
    enviar_evento(message_payload)
	
  def enviar_evento(MessagePayload):
    
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
					      message_payload=MessagePayload,  \
					      message_value=message_value),     \
				  transition=dict(prev=1,                       \
					      next=1)                           \
				  ))
         
    print 'JSON MESSAGE'
    print json_message
    
    # Se crea el socket a traves del cual se va a enviar el mensaje JSON
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Se conecta con el servidor para enviar el mensaje
    s.connect(("127.0.0.1", 50002))
    bufsize = len(json_message)

    # Se envian los datos
    totalsent = 0
    s.sendall(json.dumps(json_message))

    # Receive return value
    recvdata = s.recv(1024)
    print recvdata
    
    # Se cierra el socket
    s.close()
  
  analizar_paquete(pkt)

def ids_event():
  q = packets()
  q.register_callback(filtro)
  return q

### Main ###
def main():
  return ids_event()
