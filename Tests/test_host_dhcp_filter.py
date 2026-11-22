#!/usr/bin/env python3
"""Host-MAC DHCP filtering, dynamic identities and fail-closed state."""
import os,re,select,socket,struct,subprocess,tempfile
from pathlib import Path
from test_standalone_packets import BRIDGE,checksum,discover

def fragmented(frame):
    ip=frame[14:34]; payload=frame[34:]; parts=[]
    for offset,part in ((0,payload[:16]),(16,payload[16:])):
        header=bytearray(ip); header[2:4]=struct.pack('!H',20+len(part)); header[4:6]=b'\x23\x45'
        header[6:8]=struct.pack('!H',(0x2000 if not offset else 0)|(offset//8))
        header[10:12]=b'\0\0'; header[10:12]=struct.pack('!H',checksum(header))
        parts.append(frame[:14]+header+part)
    return parts

def main():
    output=subprocess.check_output(['/sbin/ifconfig','-a'],text=True)
    matches=re.findall(r'\bether ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})',output,re.I)
    assert matches,'no local Ethernet address to test'
    local=bytes.fromhex(matches[0].replace(':',''))
    remote=bytes.fromhex('024e53fffffe'); changed=bytes.fromhex('024e53fffffd')
    assert remote not in {bytes.fromhex(m.replace(':','')) for m in matches}
    with tempfile.TemporaryDirectory(prefix='networksharer-macs-',dir='/private/tmp') as directory:
        path=Path(directory)/'host-macs'; env=dict(os.environ,NAPTD_HOST_MAC_FILE=str(path))
        def write(contents):
            tmp=path.with_suffix('.new'); tmp.write_text(contents); tmp.chmod(0o600); os.replace(tmp,path)
        def no_reply(control,packet):
            control.send(packet); assert not select.select([control],[],[],.4)[0], 'unexpected DHCP reply'
        control,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
        proc=subprocess.Popen([str(BRIDGE),'--fd',str(child.fileno())],env=env,pass_fds=[child.fileno()],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        child.close()
        try:
            assert proc.stdout.readline().strip()==b'bridge_ready'
            no_reply(control,discover(remote,1))  # absent file fails closed
            write(matches[0]+'\n')
            no_reply(control,discover(local,2))
            packet=bytearray(discover(local,3)); packet[6:12]=remote
            no_reply(control,packet)  # DHCP hardware address is local
            packet=bytearray(discover(remote,4)); packet[6:12]=local
            no_reply(control,packet)  # Ethernet source is local
            packet=bytearray(discover(local,5)); packet[6:12]=remote
            first,second=fragmented(packet); control.send(first); no_reply(control,second)
            control.send(discover(remote,6)); assert select.select([control],[],[],3)[0]
            response=control.recv(65536); ip=response[14:]; dhcp=ip[(ip[0]&15)*4+8:]
            assert dhcp[28:34]==remote and dhcp[236:243]==b'\x63\x82\x53\x63\x35\x01\x02'
            write(matches[0]+'\n'+changed.hex(':')+'\n')
            no_reply(control,discover(changed,7))  # replacement list takes effect
            path.unlink(); no_reply(control,discover(remote,8))
            write('broken\n'); no_reply(control,discover(remote,9))
            write(matches[0]+'\n'); path.chmod(0o644); no_reply(control,discover(remote,10))
            path.unlink(); path.symlink_to('/etc/passwd'); no_reply(control,discover(remote,11))
            print('Host DHCP filtered; downstream served; updated, missing and unsafe lists handled')
        finally:
            proc.terminate()
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill();proc.wait()
            control.close()
            if proc.returncode: print(proc.stderr.read().decode(errors='replace'))
if __name__=='__main__':main()
