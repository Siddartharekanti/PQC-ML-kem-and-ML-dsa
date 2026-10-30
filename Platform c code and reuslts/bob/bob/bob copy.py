#!/usr/bin/env python3
import argparse,socket
import qsc_core as q

def main():
 p=argparse.ArgumentParser(description='Bob: QSC/2 server')
 p.add_argument('--init',action='store_true');p.add_argument('--listen',default='0.0.0.0');p.add_argument('--port',type=int,default=5004);p.add_argument('--receive-dir',default='received_bob')
 a=p.parse_args()
 if a.init:q.save_identity('bob');return
 sk,pk=q.load_identity('bob');pin=q.load_pin('alice.pub.json','alice')
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
  server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  server.bind((a.listen,a.port));server.listen(5)
  q.out('[LISTENING]',a.listen,a.port)
  while True:
   sock,addr=server.accept();q.out('[CONNECTED]',addr)
   with sock:
    try:
     sock.settimeout(30);ch=q.handshake(sock,'server','bob',sk,pk,'alice',pin)
     sock.settimeout(None);q.chat(ch,a.receive_dir)
    except (q.ProtocolError,OSError,ValueError,KeyError) as e:q.out('[REJECTED]',type(e).__name__,str(e))
if __name__=='__main__':
 try:main()
 except (q.ProtocolError,OSError,ValueError,KeyError) as e:q.out('[ERROR]',str(e))
