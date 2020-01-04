from boofuzz import *
from boofuzz import pedrpc
# User defined variables
targetIp_Str = '127.0.0.1'
targetPort_Int = 8021
procmonIp_Str = '127.0.0.1'
procmonPort_Int = 26002
procName_Str = 'ftp-asan'
procStartCmd_Str = '/home/kali/fuzzing/victims/target1-ftp/ftp-asan'
procStopCmd_Str = 'killall ftp-asan'
netmonIp_Str = '127.0.0.1'
netmonPort_Int = 26001
# Automatic defined variables
import time
time_Str = time.strftime("%Y%m%d%H%M%S")
print("time: " + time_Str)
sessionFileName_Str = time_Str + ".ftp-taget1.session"
print("sessionFileName: " + sessionFileName_Str)
# BooFuzz defined variables
s_static = Static
s_delim = Delim
s_string = String
session = sessions.Session(session_filename=sessionFileName_Str,
sleep_time=1.0)
target = sessions.Target(SocketConnection(host=targetIp_Str,
port=targetPort_Int))
# Optionally monitor the process for segfaults
'''
python /home/kali/fuzzing/fuzzers/boofuzz/process_monitor_unix.py -c /home/kali/fuzzing/sessions/boofuzzruns/procmons/$(date +"%Y%m%d%H%M").procmon
'''
target.procmon = pedrpc.Client(procmonIp_Str, procmonPort_Int)
target.procmon_options = {"proc_name": procName_Str,
"start_commands": [procStartCmd_Str], "stop_commands":
[procStopCmd_Str]}
# Optionally enable pcap creation
'''
python /home/kali/fuzzing/fuzzers/boofuzz/network_monitor_unix.py -d 2 -P /home/kali/fuzzing/sessions/boofuzzRuns/netmons/
'''
#target.netmon = pedrpc.Client(netmonIp_Str, netmonPort_Int)
session.add_target(target)
# Import HTTP BooFuzz Templates; Check out python files within /opt/boofuzz/requests for detials
#import sys
#sys.path.insert(0, '/home/kali/fuzzing/fuzzers/boofuzz/requests')
#import http_get
# import http_header
# import http_post
# Connect & Fuzz
# s_get("example001") -> s_initialize("example001") inside /opt/boofuzz/requests/*.py files
s_initialize("user")
s_string("USER")
s_delim(" ")
s_string("anonymous")
s_static("\r\n")

s_initialize("pass")
s_string("PASS")
s_delim(" ")
s_string("james")
s_static("\r\n")

s_initialize("stor")
s_string("STOR")
s_delim(" ")
s_string("AAAA")
s_static("\r\n")

s_initialize("retr")
s_string("RETR")
s_delim(" ")
s_string("AAAA")
s_static("\r\n")

session.connect(s_get("user"))
session.connect(s_get("user"), s_get("pass"))
session.connect(s_get("pass"), s_get("stor"))
session.connect(s_get("pass"), s_get("retr"))

session.fuzz()

