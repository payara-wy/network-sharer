#!/usr/bin/env python3
"""Root-only integration test on two temporary feth interfaces, without a phone."""
import concurrent.futures
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT/'build'/'局域网代理共享器正式版'/'局域网代理共享器.app'
ENGINE = APP/'Contents/Resources/engine.sh'
PROBE = ROOT/'build'/'networksharer-feth-dhcp-probe'

def run(*args, check=True, timeout=20):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, check=check, timeout=timeout)

def alive(pid):
    result = run('/bin/ps', '-p', str(pid), '-o', 'stat=', check=False)
    return result.returncode == 0 and result.stdout.strip() and not result.stdout.strip().startswith('Z')

def state(directory):
    try:
        return dict(line.split('=',1) for line in (directory/'state').read_text().splitlines() if '=' in line)
    except FileNotFoundError: return {}

def owned_interfaces(directory, bridge, excluded):
    """Snapshot only interfaces explicitly recorded by this session."""
    records={}
    for line in (directory/'interfaces').read_text().splitlines():
        parts=line.split()
        if len(parts) not in (3,4): raise RuntimeError('会话接口记录无效')
        kind,name,mac=parts[:3]
        if len(parts)==4 and (not parts[3].isdigit() or int(parts[3])<1):
            raise RuntimeError('会话接口编号无效')
        if kind not in ('bridge','feth') or not re.fullmatch(kind+r'[0-9]+',name) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',mac):
            raise RuntimeError('会话接口记录无效')
        if name in excluded: raise RuntimeError('会话接口与现有端口冲突')
        records[name]=mac.lower()
    if bridge not in records or len([n for n in records if n.startswith('feth')])!=2:
        raise RuntimeError('内部接口记录不完整')
    return records

def interface_gone(name, expected_mac):
    result=run('/sbin/ifconfig',name,check=False)
    if result.returncode: return True
    found=re.search(r'^\s*ether\s+([0-9a-fA-F:]+)',result.stdout,re.MULTILINE)
    # An unrelated replacement must not be deleted or mistaken for our interface.
    return bool(found and found.group(1).lower()!=expected_mac)

def wait_for(check, seconds, description):
    deadline = time.monotonic()+seconds
    while time.monotonic()<deadline:
        result=check()
        if result: return result
        time.sleep(.2)
    raise RuntimeError('timed out: '+description)

def read_parent(pid):
    value=run('/bin/ps','-p',pid,'-o','ppid=').stdout.strip()
    return int(value)

def gui_process(uid):
    account=pwd.getpwuid(uid)
    def demote():
        os.setgroups([]); os.setgid(account.pw_gid); os.setuid(uid)
    return subprocess.Popen(['/bin/sleep','600'], preexec_fn=demote, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def classify_renewals(retained, attempts, silent=()):
    """Keep timed-out leases reserved: clients may still consider them valid."""
    renewed=set(); rejected=set(); uncertain=set(); offline=set(silent) & set(retained)
    for key,value in retained.items():
        if key in offline: continue
        code,address=attempts[key]
        if code==0 and address==value: renewed.add(key)
        elif code==2: rejected.add(key)  # A received DHCP NAK invalidates this lease.
        else: uncertain.add(key)
    return renewed,rejected,uncertain,offline

def assess_lease_cycle(retained, attempts, allocated, silent=()):
    renewed,rejected,uncertain,offline=(classify_renewals(retained,attempts,silent)
                                      if attempts is not None else (set(),set(),set(),set()))
    active={key:value for key,value in retained.items() if key not in rejected}
    overlap=set(allocated.values()) & set(active.values())
    summary={'renewed':len(renewed),'renew_rejected':len(rejected),
             'renew_not_acknowledged':len(uncertain),'silent_old_clients':len(offline),
             'reused_unexpired_or_unconfirmed':len(overlap)}
    active.update(allocated)
    return active,summary

def lease_cycles_pass(cycles, crash_reused=0):
    return not crash_reused and not any(c['renew_not_acknowledged'] or c['reused_unexpired_or_unconfirmed'] for c in cycles)

def prepare_isolated_lease_test(parent):
    # Only edit the validator's disposable copy, never the installed product.
    root=ROOT.resolve(); workspace=root.parent
    if root.name!='root' or workspace.parent!=Path('/private/tmp') or not re.fullmatch(
            r'networksharer-validation-[0-9A-Fa-f-]{36}',workspace.name):
        raise RuntimeError('租约测试只能在验证器的临时副本中运行')
    app=APP.resolve(strict=True)
    if APP.is_symlink() or not app.is_relative_to(root) or ENGINE.is_symlink() or \
            not ENGINE.resolve(strict=True).is_relative_to(app) or ENGINE.stat().st_nlink!=1:
        raise RuntimeError('测试应用的脚本路径不安全')
    original='/private/var/db/com.local.lansharer'
    replacement=str(parent/'com.local.lansharer')
    engine=ENGINE.read_text()
    if engine.count(original)!=1: raise RuntimeError('租约测试路径布局不匹配')
    ENGINE.write_text(engine.replace(original,replacement))
    run('/usr/bin/clang','-mmacosx-version-min=14.0','-O2','-Wall','-Wextra',
        '-DNETWORKSHARER_LEASE_PARENT="'+str(parent)+'"',
        ROOT/'Tests/lease_store.c','-o',APP/'Contents/MacOS/lease_store',timeout=45)
    run('/usr/bin/codesign','--force','--sign','-',APP,timeout=45)
    run('/usr/bin/codesign','--verify','--deep','--strict',APP,timeout=45)

def main():
    if os.geteuid()!=0 or len(sys.argv)!=3: raise RuntimeError('需要管理员权限及测试用户编号、Wi-Fi 接口')
    uid=int(sys.argv[1]); source=sys.argv[2]
    if not re.fullmatch(r'en[0-9]+',source) or uid<=0 or not ENGINE.is_file() or not PROBE.is_file():
        raise RuntimeError('测试组件或接口不可用')
    parent=Path(tempfile.mkdtemp(prefix='networksharer-feth-leases-',dir='/private/tmp'))
    cleanup={'safe':True}
    try:
        prepare_isolated_lease_test(parent)
        report=run_integration(uid,source,cleanup)
    finally:
        if cleanup['safe']: shutil.rmtree(parent)
        else: print('测试会话未完全退出，保留隔离租约目录：'+str(parent),file=sys.stderr,flush=True)
    report['lease_test_directory_cleanup']=True
    print(json.dumps(report,ensure_ascii=False),flush=True)
    if report['result']!='passed': raise SystemExit(1)

def run_integration(uid,source,cleanup):
    initial=set(run('/sbin/ifconfig','-l').stdout.split())
    feth=[]; feth_macs={}; gui=None; runtime=None; report={'cycles':[]}
    try:
        for _ in range(2):
            name=run('/sbin/ifconfig','feth','create').stdout.strip()
            if not re.fullmatch(r'feth[0-9]+',name) or name in initial or name in feth:
                raise RuntimeError('无法安全确认临时接口')
            feth.append(name)
            info=run('/sbin/ifconfig',name).stdout
            match=re.search(r'^\s*ether\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})',info,re.MULTILINE)
            if not match: raise RuntimeError('无法确认测试端口身份')
            feth_macs[name]=match.group(1).lower()
        run('/sbin/ifconfig',feth[0],'peer',feth[1]); run('/sbin/ifconfig',feth[0],'up'); run('/sbin/ifconfig',feth[1],'up')
        gui=gui_process(uid)
        def start():
            nonlocal runtime
            p=run('/bin/bash',ENGINE,'launch',uid,gui.pid,source,'direct','0','114.114.114.114','-',feth[0],check=False,timeout=25)
            if p.returncode: raise RuntimeError('启动共享失败：'+p.stderr.strip()[:200])
            raw=p.stdout.strip()
            if not re.fullmatch(r'/private/tmp/lanproxy\.[A-Za-z0-9]{8}',raw): raise RuntimeError('会话路径无效')
            runtime=Path(raw)
            (runtime/'auth').write_bytes(b'\0\0'); (runtime/'control').write_text('READY\n')
            def ready():
                s=state(runtime)
                if s.get('state')=='error': raise RuntimeError('共享错误：'+s.get('message',''))
                return s if s.get('state')=='running' else None
            s=wait_for(ready,25,'共享桥接')
            if not re.fullmatch(r'bridge[0-9]+',s.get('bridge','')): raise RuntimeError('网桥名称无效')
            pid=int(s['daemon_pid']); controller=read_parent(pid)
            command=run('/bin/ps','-p',controller,'-o','command=').stdout
            if str(ENGINE) not in command or str(runtime) not in command: raise RuntimeError('无法确认控制进程身份')
            return s,controller
        def stop(s,controller,kill_controller=False):
            nonlocal runtime
            directory=runtime; bridge=s['bridge']
            interfaces=owned_interfaces(directory,bridge,initial|set(feth))
            if kill_controller: os.kill(controller,signal.SIGKILL)
            else: (directory/'control').write_text('STOP\n')
            wait_for(lambda:not alive(controller),15,'控制进程退出')
            wait_for(lambda:not alive(int(s['daemon_pid'])) and not alive(int(s['gateway_pid'])),15,'转发进程退出')
            def bridge_gone(): return run('/sbin/ifconfig',bridge,check=False).returncode!=0
            wait_for(bridge_gone,15,'临时网桥释放')
            wait_for(lambda:all(interface_gone(name,mac) for name,mac in interfaces.items()),15,'内部虚拟端口释放')
            wait_for(lambda:not directory.exists(),12,'会话目录清理')
            runtime=None
        def allocate(ids):
            def one(i):
                p=run(PROBE,feth[1],i,check=False,timeout=12)
                return i,p.returncode,p.stdout.strip(),p.stderr.strip()
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                values=list(pool.map(one,ids))
            errors=[(i,err) for i,code,_,err in values if code]
            if errors: raise RuntimeError('DHCP 分配失败：'+str(errors[:3]))
            addresses=[value for _,_,value,_ in values]
            if len(set(addresses))!=len(addresses): raise RuntimeError('同一会话出现重复地址')
            return dict((i,value) for i,_,value,_ in values)
        def preflight(bridge):
            # Only inspect the two temporary feth ports and the test-created bridge.
            # A sequential client distinguishes a broken probe from a concurrency failure.
            captures=[]
            for interface in (feth[0],feth[1],bridge):
                process=subprocess.Popen(['/usr/sbin/tcpdump','-l','-n','-e','-i',interface,
                                          'udp and (port 67 or port 68)'],
                                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                captures.append((interface,process))
            try:
                time.sleep(1)
                attempts=[]
                for _ in range(3):
                    p=run(PROBE,feth[1],999,check=False,timeout=12)
                    attempts.append((p.returncode,p.stdout.strip(),p.stderr.strip()))
                    if p.returncode==0: break
                    time.sleep(1)
            finally:
                traces={}
                for interface,process in captures:
                    if process.poll() is None: process.send_signal(signal.SIGINT)
                    try: out,err=process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill(); out,err=process.communicate()
                    traces[interface]={'packets':out.strip().splitlines()[:8],
                                       'capture_status':err.strip().splitlines()[-3:]}
            if attempts[-1][0]:
                bridge_info=run('/sbin/ifconfig',bridge,check=False).stdout
                relevant=[line.strip() for line in bridge_info.splitlines()
                          if line.strip().startswith(('member:','status:','flags='))]
                raise RuntimeError('DHCP 单设备预检失败：'+json.dumps(
                    {'attempts':attempts,'captures':traces,'bridge':relevant},ensure_ascii=False))
            return attempts[-1][1]
        retained={}
        for cycle in range(5):
            s,controller=start()
            if cycle==0:
                retained[999]=preflight(s['bridge'])
                # Remove only the bridge whose identity this test session recorded.
                bridge=s['bridge']; interfaces=owned_interfaces(runtime,bridge,initial|set(feth))
                info=run('/sbin/ifconfig','-v',bridge).stdout
                mac=re.search(r'^\s*ether\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})',info,re.MULTILINE)
                index=re.search(r'\bindex\s+([0-9]+)',info.splitlines()[0])
                if not mac or not index or mac.group(1).lower()!=interfaces[bridge]:
                    raise RuntimeError('无法确认测试网桥身份')
                old_index=index.group(1)
                run('/sbin/ifconfig',bridge,'destroy')
                recovery_observations=[]
                def bridge_recovered():
                    current=state(runtime)
                    if not runtime.exists():
                        raise RuntimeError('恢复时会话消失：'+json.dumps(recovery_observations[-8:],ensure_ascii=False))
                    if current.get('state')=='error':
                        raise RuntimeError('网桥恢复失败：'+current.get('message',''))
                    sample=(current.get('state',''),current.get('message',''),current.get('bridge',''))
                    if not recovery_observations or sample!=recovery_observations[-1]:
                        recovery_observations.append(sample)
                    if current.get('state')!='running' or not re.fullmatch(r'bridge[0-9]+',current.get('bridge','')):
                        return None
                    info=run('/sbin/ifconfig','-v',current['bridge'],check=False).stdout
                    lines=info.splitlines(); match=re.search(r'\bindex\s+([0-9]+)',lines[0]) if lines else None
                    # macOS may immediately reuse both the bridge name and index.
                    # We have already destroyed the verified test-owned bridge;
                    # a waiting-to-running transition with the original children
                    # and a newly existing bridge demonstrates recovery.
                    observed_wait=any(item[0]=='waiting' and item[1] in ('正在检查共享网桥','正在恢复共享网桥')
                                      for item in recovery_observations)
                    same_children=(current.get('daemon_pid')==s.get('daemon_pid') and
                                   current.get('gateway_pid')==s.get('gateway_pid'))
                    return current if match and observed_wait and same_children else None
                try:
                    s=wait_for(bridge_recovered,30,'共享网桥自动重建')
                except RuntimeError as error:
                    raise RuntimeError(str(error)+'；状态：'+json.dumps(recovery_observations[-8:],ensure_ascii=False))
                renewed=run(PROBE,feth[1],999,retained[999],check=False,timeout=12)
                if renewed.returncode or renewed.stdout.strip()!=retained[999]:
                    raise RuntimeError('网桥恢复后未能续用原有地址')
                report['bridge_recovery']=True
            attempts=None
            silent={999,1000,1001} & set(retained) if cycle else set()
            if retained and cycle:
                def renew(item):
                    key,value=item
                    p=run(PROBE,feth[1],key,value,check=False,timeout=10)
                    return key,(p.returncode,p.stdout.strip())
                # The preflight lease was just issued in cycle 0; it needs no renewal.
                with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                    attempts=dict(pool.map(renew,((k,v) for k,v in retained.items() if k not in silent)))
            allocated=allocate(range(1000+cycle*20,1008+cycle*20))
            retained,lease_summary=assess_lease_cycle(retained,attempts,allocated,silent)
            report['cycles'].append({'cycle':cycle+1,'new_clients':len(allocated),
                                     **lease_summary,'controller_killed':cycle==2})
            stop(s,controller,kill_controller=cycle==2)
        # Kill only the synthetic GUI process and verify the app cleans up itself.
        s,controller=start(); interfaces=owned_interfaces(runtime,s['bridge'],initial|set(feth)); gui.kill(); gui.wait(timeout=5)
        wait_for(lambda:not alive(controller),15,'界面退出后的控制进程清理')
        wait_for(lambda:not alive(int(s['daemon_pid'])) and not alive(int(s['gateway_pid'])),15,'界面退出后的后台清理')
        wait_for(lambda:run('/sbin/ifconfig',s['bridge'],check=False).returncode!=0,15,'界面退出后的网桥清理')
        wait_for(lambda:all(interface_gone(name,mac) for name,mac in interfaces.items()),15,'界面退出后的内部端口清理')
        wait_for(lambda:not runtime.exists(),12,'界面退出后的会话清理')
        runtime=None; report['gui_crash_cleanup']=True; report['internal_ports_cleanup']=True
        gui=gui_process(uid); s,controller=start(); allocated=allocate(range(3000,3004))
        _,crash_summary=assess_lease_cycle(retained,{},allocated,set(retained))
        report['crash_reused_pending_leases']=crash_summary['reused_unexpired_or_unconfirmed']
        stop(s,controller)
        report['restart_after_crash_clients']=len(allocated)
        incomplete=not lease_cycles_pass(report['cycles'],report['crash_reused_pending_leases'])
        report['result']='failed' if incomplete else 'passed'
        if incomplete: report['message']='旧租约未确认或新分配地址与可能仍有效的旧地址冲突'
    finally:
        cleanup['safe']=False
        if runtime and runtime.exists():
            try: (runtime/'control').write_text('STOP\n')
            except OSError: pass
        if gui and gui.poll() is None:
            gui.terminate()
            try: gui.wait(timeout=5)
            except subprocess.TimeoutExpired: gui.kill(); gui.wait(timeout=5)
        for name in reversed(feth):
            mac=feth_macs.get(name)
            if not mac: raise RuntimeError('测试端口身份不明，未自动销毁：'+name)
            if not interface_gone(name,mac):
                result=run('/sbin/ifconfig',name,'destroy',check=False)
                if result.returncode or not interface_gone(name,mac):
                    raise RuntimeError('测试端口未能清理：'+name)
        if runtime and runtime.exists():
            wait_for(lambda:not runtime.exists(),20,'失败会话清理')
        cleanup['safe']=True
    report['test_ports_cleanup']=True
    return report

if __name__=='__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'result':'failed','message':str(error)},ensure_ascii=False),flush=True)
        raise SystemExit(1)
