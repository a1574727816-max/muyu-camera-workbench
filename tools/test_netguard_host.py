"""Behavior checks for bounded logs and kernel-lock recovery; isolated Linux temp files."""
import argparse,json,os,resource,signal,subprocess,tempfile,time
from pathlib import Path

ap=argparse.ArgumentParser();ap.add_argument('--binary',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
binary=str(args.binary.resolve());result={'complete':False,'checks':{}}
def wait(test,seconds=4):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        if test():return
        time.sleep(.02)
    raise AssertionError('Timed out')
with tempfile.TemporaryDirectory(prefix='netguard-test-') as d:
    root=Path(d);pid=root/'service.pid';prefix=root/'service'
    oversized=prefix.with_suffix('.log');oversized.write_bytes(b'Z'*300000)
    writer=root/'writer.py';big=root/'child-output.bin';limits=root/'child-limits.json'
    writer.write_text('import os,resource,json\nfrom pathlib import Path\n'
        +f'Path({str(limits)!r}).write_text(json.dumps(resource.getrlimit(resource.RLIMIT_FSIZE)))\n'
        +f'Path({str(big)!r}).write_bytes(b"B"*524288)\n'
        +'for i in range(1024):os.write(1,b"A"*4096)\n'
        +'os.write(1,b"NETGUARD_AFTER_FLOOD\\n")\n')
    def inherited_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(131072,resource.RLIM_INFINITY))
    p=subprocess.run([binary,'log',str(pid),str(prefix),'/usr/bin/python3',str(writer)],capture_output=True,timeout=10,preexec_fn=inherited_limit)
    assert p.returncode==0,p.stderr
    logs=list(root.glob('service.log'))+list(root.glob('service.previous'))
    assert len(logs)==2 and all(f.stat().st_size<=65536 for f in logs)
    assert b'NETGUARD_AFTER_FLOOD' in prefix.with_suffix('.log').read_bytes()
    assert big.stat().st_size==524288 and json.loads(limits.read_text())==[-1,-1]
    assert not pid.exists() and not Path(str(pid)+'.guard').exists()
    result['checks']['more_than_4mib_logs_kept_within_128kib']=True
    result['checks']['oversized_existing_log_compacted']=True
    result['checks']['child_file_limit_cleared_and_512kib_write_passed']=True
    lock=root/'kernel.lock';lock.mkdir();owner=root/'owner';log=root/'network';duplicate=root/'duplicate-ran'
    def start():
        p=subprocess.Popen([binary,'lock',str(lock),str(owner),str(log),'/bin/sleep','60'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        wait(lambda:owner.exists() and int(owner.read_text().split()[0])==p.pid)
        return p,int(owner.read_text().split()[2])
    def child_alive(child):
        try:
            data=Path('/proc')/str(child)/'stat'
            return data.exists() and data.read_text().split(') ',1)[1][0]!='Z'
        except FileNotFoundError:return False
    first,child=start()
    try:
        p=subprocess.run([binary,'lock',str(lock),str(owner),str(log),'/usr/bin/touch',str(duplicate)],timeout=3)
        assert p.returncode==0 and not duplicate.exists() and first.poll() is None
        os.kill(child,signal.SIGKILL);first.wait(timeout=4)
        assert lock.exists()
        result['checks']['preexisting_directory_and_duplicate_guard_handled']=True
        second,child2=start()
        os.kill(second.pid,signal.SIGKILL);second.wait(timeout=3)
        wait(lambda:not child_alive(child2))
        third,child3=start()
        third.terminate();third.wait(timeout=4)
        wait(lambda:not child_alive(child3))
        result['checks']['main_sigkill_released_lock']=True
        result['checks']['guard_sigkill_did_not_leave_inherited_lock']=True
        result['checks']['normal_termination_stopped_child']=True
        unrelated=subprocess.Popen(['/bin/sleep','30'])
        try:
            owner.write_text(f'999999 1 {unrelated.pid} 1\n')
            fourth,child4=start();assert unrelated.poll() is None
            fourth.terminate();fourth.wait(timeout=4)
            result['checks']['stale_pid_starttime_mismatch_did_not_kill_unrelated_process']=True
        finally:unrelated.terminate();unrelated.wait()
    finally:
        if first.poll() is None:first.terminate();first.wait(timeout=6)
    result['complete']=True
args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
