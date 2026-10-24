"""CCTV VOD sample 3.bin, private NAL signature 79 01 01 09 only.
Usage: python3 decrypt_cctv_vod.py input.bin output.ts
Requires companion decrypt_cctv_ts.py (standard library only).
"""
import re, struct, sys, json, hashlib
from pathlib import Path
import decrypt_cctv_ts as ts
from decrypt_cctv_ts import tea16_decrypt
def keeloq16(block,key):
 x=int.from_bytes(block,'little');k=int.from_bytes(key[:8],'little')
 for r in range(16):
  idx=(x&1)|((x>>7)&2)|((x>>17)&4)|((x>>22)&8)|((x>>26)&16)
  bit=((x>>31)^(x>>15)^(k>>((15-r)&63))^(0x3a5c742e>>idx))&1
  x=((x<<1)|bit)&0xffffffff
 return x.to_bytes(4,'little')
def dec(n):
 if n[0]&31 not in (1,5) or len(n)<=128:return n
 b=bytearray(re.sub(b'\x00\x00\x03(?=[\x00-\x03])',b'\0\0',n));typ=b[0]&31;start=5 if typ==5 else 1;k=bytes(b[start:start+16]);step=[k[j]|(160+32*j) for j in range(6)][int.from_bytes(k[:4],'little')%6];size=8 if typ==5 else 4
 for p in range(64,len(b)-15,step):
  b[p:p+size]=tea16_decrypt(bytes(b[p:p+size]),struct.unpack('<4I',k)) if typ==5 else keeloq16(b[p:p+size],k)
 return bytes(b)

def main():
 if len(sys.argv)!=3: raise SystemExit(__doc__)
 data=Path(sys.argv[1]).read_bytes();packets=ts.split_packets(data);pid=ts.find_h264_pid(packets)
 groups=ts.video_pes_groups(packets,pid);active=False;counts={};slices=0
 for indices in groups:
  pes=b"".join(bytes(packets[i][ts.payload_start(packets[i]):]) for i in indices)
  hl=9+pes[8];es=pes[hl:];matches=list(ts.START_CODE.finditer(es));out=[]
  for j,m in enumerate(matches):
   end=matches[j+1].start() if j+1<len(matches) else len(es)
   n=es[m.end():end].rstrip(b"\0")
   if not n: continue
   typ=n[0]&31;counts[typ]=counts.get(typ,0)+1
   if typ==25:
    if n[:4]!=bytes.fromhex("79010109"): raise ValueError("Unsupported private NAL mode")
    active=True;continue
   if typ in (1,5) and len(n)>128:
    if not active: raise ValueError("Missing private NAL mode marker")
    n=dec(n);slices+=1
   out.append(m.group()+n)
  body=b"".join(out);header=bytearray(pes[:hl])
  if int.from_bytes(header[4:6],"big"):header[4:6]=(len(header)+len(body)-6).to_bytes(2,"big")
  ts.write_pes_to_original_slots(packets,indices,bytes(header)+body)
 ts.normalize_video_cc(packets,pid);result=b"".join(packets);Path(sys.argv[2]).write_bytes(result)
 print(json.dumps({"video_pid":pid,"video_pes":len(groups),"nal_counts":counts,"decrypted_slices":slices,"input_sha256":hashlib.sha256(data).hexdigest(),"output_sha256":hashlib.sha256(result).hexdigest()},indent=2))
if __name__=="__main__":main()
