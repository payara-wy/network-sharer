#!/usr/bin/env python3
"""Boundary and malformed frame tests for the frozen direct-mode UDP path."""
import importlib.util
import json
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('audit',ROOT/'Tests/run_readonly_audit.py')
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)

with audit.Gateway(audit.WORK/'gateway-asan') as gateway:
    with audit.datagram() as client,audit.datagram() as server:
        size=1024*1024
        client.setsockopt(0x0000ffff,0x1001,size)
        client.setsockopt(0x0000ffff,0x1002,size)
        server.setsockopt(0x0000ffff,0x1001,size)
        server.setsockopt(0x0000ffff,0x1002,size)
        control,relay=audit.associate(gateway.port)
        try:
            print('buffers',client.getsockopt(0xffff,0x1002),server.getsockopt(0xffff,0x1002),flush=True)
            print('relay',relay,flush=True)
            payload=bytes((index*131)&255 for index in range(9000))
            client.sendto(audit.header(server.getsockname()[1])+payload,relay)
            print('sent client frame',flush=True)
            received,peer=server.recvfrom(70000)
            print('upstream server got',len(received),flush=True)
            assert received==payload,(len(received),len(payload))
            server.sendto(payload,peer)
            answer,_=client.recvfrom(70000)
            result={'sent_payload_bytes':len(payload),'received_payload_bytes':len(answer)-10,
                    'original_and_forwarded_equal':answer[10:]==payload,
                    'tail_missing':answer[10:]!=payload and payload.startswith(answer[10:]),
                    'truncation_flag_present':False}
        finally:control.close()
output=audit.OUT/'evidence/udp-truncation-result.json'
output.write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
