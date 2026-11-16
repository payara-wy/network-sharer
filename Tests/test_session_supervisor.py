#!/usr/bin/env python3
"""Exercise the real process supervisor without changing host network interfaces."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]

def until(predicate, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result: return result
        time.sleep(.05)
    raise AssertionError('timed out waiting for supervisor state')

def alive(pid):
    try: os.kill(pid, 0); return True
    except ProcessLookupError: return False

with tempfile.TemporaryDirectory(prefix='networksharer-supervisor-test-', dir='/private/tmp') as tmp:
    root = Path(tmp)
    supervisor = root/'supervisor'
    lock = root/'session.lock'
    subprocess.run(['/usr/bin/clang', '-O2', '-Wall', '-Wextra',
                    '-DNETWORKSHARER_SESSION_ROOT="'+str(root)+'"',
                    '-DNETWORKSHARER_LOCK_PATH="'+str(lock)+'"',
                    str(ROOT/'Sources/session_supervisor.c'), '-o', str(supervisor)], check=True)
    engine = root/'fake-engine.sh'
    engine.write_text('''#!/bin/bash
dir=$2; gui=$3
trap '/bin/rm -rf "$dir"; exit 0' TERM
printf '%s\\n' "$$" > "$dir/controller.pid"
while kill -0 "$gui" 2>/dev/null; do /bin/sleep .1; done
/bin/rm -rf "$dir"
''')
    def new_session(marked=True, owner_pid=None):
        d = root/('networksharer.'+uuid.uuid4().hex[:8])
        d.mkdir(mode=0o711)
        if marked: (d/'session.marker').write_text('NetworkSharerSession/1\n')
        (d/'session.owner').write_text(str(owner_pid if owner_pid is not None else os.getpid())+'\n')
        (d/'state').write_text('state=starting\n')
        return d
    def new_gui():
        return subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    def launch(directory, gui):
        return subprocess.Popen([str(supervisor), str(directory), str(engine), str(os.getuid()), str(gui.pid),
                                 'en0', 'direct', '0', '1.1.1.1', '-', 'feth0'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def status(directory):
        try: return (directory/'supervisor.status').read_text().strip()
        except FileNotFoundError: return ''
    def controller(directory):
        try: return int((directory/'controller.pid').read_text())
        except (FileNotFoundError, ValueError): return 0

    departed = new_gui(); departed.kill(); departed.wait(timeout=3)
    stale = new_session(owner_pid=departed.pid)
    dead_controller = new_session()
    (dead_controller/'state').write_text('state=running\ndaemon_pid='+str(departed.pid)+'\n')
    unmarked = new_session(marked=False)
    target = root/'unrelated'; target.mkdir()
    link = root/('networksharer.'+uuid.uuid4().hex[:8]); link.symlink_to(target, target_is_directory=True)
    gui = new_gui(); processes = []
    try:
        first = new_session(); one = launch(first, gui); processes.append(one)
        assert until(lambda: status(first)) == 'ready'
        child = until(lambda: controller(first))
        assert not stale.exists() and not dead_controller.exists() and unmarked.exists() and link.is_symlink() and target.exists()

        second = new_session(); two = launch(second, gui); processes.append(two)
        assert until(lambda: status(second)) == 'busy'
        assert two.wait(timeout=3) != 0

        os.kill(child, signal.SIGKILL)
        assert until(lambda: (first/'state').read_text().startswith('state=error') if (first/'state').exists() else False)
        assert one.wait(timeout=9) == 0
        until(lambda: not first.exists(), seconds=8)

        third = new_session(); three = launch(third, gui); processes.append(three)
        assert until(lambda: status(third)) == 'ready'
        child = until(lambda: controller(third))
        gui.kill(); gui.wait(timeout=3)
        assert three.wait(timeout=9) == 0 and not third.exists() and not alive(child)

        # A killed supervisor must not unlock while its controller is alive.
        gui = new_gui()
        fourth = new_session(); four = launch(fourth, gui); processes.append(four)
        assert until(lambda: status(fourth)) == 'ready'
        child = until(lambda: controller(fourth))
        four.kill(); four.wait(timeout=3)
        fifth = new_session(); five = launch(fifth, gui); processes.append(five)
        assert until(lambda: status(fifth)) == 'busy'
        five.wait(timeout=3)
        gui.kill(); gui.wait(timeout=3)
        until(lambda: not alive(child), seconds=8)
        sixth_gui = new_gui(); gui = sixth_gui
        sixth = new_session(); six = launch(sixth, gui); processes.append(six)
        assert until(lambda: status(sixth)) == 'ready'
        gui.kill(); gui.wait(timeout=3)
        assert six.wait(timeout=9) == 0
    finally:
        if gui.poll() is None: gui.kill(); gui.wait(timeout=3)
        for process in processes:
            if process.poll() is None: process.kill(); process.wait(timeout=3)
print('Supervisor: exclusive sessions, stale cleanup, controller kill, GUI exit and supervisor loss passed')
