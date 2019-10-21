import subprocess, os, time, signal

def exec_command(command, timeout):
    """call shell-command and either return its output or kill it
    if it doesn't normally exit within timeout seconds and return None"""
    
    cmd = command.split(" ")
    t1 = time.time()
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while process.poll() is None:
        time.sleep(0.01)
        t2 = time.time()
        if t2-t1 > timeout:
            os.kill(process.pid, signal.SIGKILL)
            os.waitpid(-1, os.WNOHANG)
            return None
    return process.stdout.readlines()

def popen_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = p.communicate()
    return output.strip()

res = popen_command("ifconfig ens34 | grep 'bytes' | cut -d ':' -f2 | cut -d ' ' -f1")
print(res)

res = popen_command("netstat -n | awk '/:80/ {++S[$NF]} END {for(a in S) print a, S[a]}' | grep 'ESTABLISHED' | cut -d ' ' -f2")
print(res)

res = popen_command("cat ./data/ip2latlon.json | grep 255.255.240.0")
print(res)
