from boofuzz import *
from boofuzz import pedrpc
# User defined variables
targetIp_Str = '127.0.0.1'
targetPort_Int = 8080
procmonIp_Str = '127.0.0.1'
procmonPort_Int = 26002
procName_Str = 'angryspider.noflags'
procStartCmd_Str = '/opt/angrySpider/angryspider.noflags'
procStopCmd_Str = 'killall angryspider.noflags'
netmonIp_Str = '127.0.0.1'
netmonPort_Int = 26001
# Automatic defined variables
import time
time_Str = time.strftime("%Y%m%d%H%M%S")
print("time: " + time_Str)
sessionFileName_Str = time_Str + ".patBrown.session"
print("sessionFileName: " + sessionFileName_Str)
# BooFuzz defined variables
s_static = Static
s_delim = Delim
s_string = String
sess = sessions.Session(session_filename=sessionFileName_Str,
sleep_time=.25)
target = sessions.Target(SocketConnection(host=targetIp_Str,
port=targetPort_Int))
# Optionally monitor the process for segfaults
'''
mkdir -p /opt/boofuzzRuns/procmons/
cd /opt/boofuzz
python process_monitor_unix.py -c /opt/boofuzzRuns/procmons/$(date
+"%Y%m%d%H%M").procmon
'''
target.procmon = pedrpc.Client(procmonIp_Str, procmonPort_Int)
target.procmon_options = {"proc_name": procName_Str,
"start_commands": [procStartCmd_Str], "stop_commands":
[procStopCmd_Str]}
# Optionally enable pcap creation
'''
mkdir -p /opt/boofuzzRuns/netmons/
cd /opt/boofuzz
cp network_monitor.py network_monitor_unix.py
python network_monitor_unix.py -d 2 -P /opt/boofuzzRuns/netmons/
'''
#target.netmon = pedrpc.Client(netmonIp_Str, netmonPort_Int)
sess.add_target(target)
# Import HTTP BooFuzz Templates; Check out python files within
/opt/boofuzz/requests for detials
import sys
sys.path.insert(0, '/opt/boofuzz/requests')
import http_get
# import http_header
# import http_post
# Connect & Fuzz
# s_get("example001") -> s_initialize("example001") inside
/opt/boofuzz/requests/*.py files
print("session importing get requests")
sess.connect(sess.root, s_get("HTTP VERBS"))
sess.connect(sess.root, s_get("HTTP METHOD"))
sess.connect(sess.root, s_get("HTTP REQ"))
'''
print("session importing header requests")
sess.connect(sess.root, s_get("HTTP HEADER COOKIE"))
sess.connect(sess.root, s_get("HTTP HEADER CONTENTLENGTH"))
sess.connect(sess.root, s_get("HTTP HEADER CLOSE"))
sess.connect(sess.root, s_get("HTTP HEADER COOKIE"))
sess.connect(sess.root, s_get("HTTP HEADER AUTHORIZATION"))
sess.connect(sess.root, s_get("HTTP HEADER ACCEPT"))
sess.connect(sess.root, s_get("HTTP HEADER ACCEPTCHARSET"))
sess.connect(sess.root, s_get("HTTP HEADER ACCEPTDATETIME"))
sess.connect(sess.root, s_get("HTTP HEADER ACCEPTENCODING"))
sess.connect(sess.root, s_get("HTTP HEADER ACCEPTLANGUAGE"))
sess.connect(sess.root, s_get("HTTP HEADER AUTHORIZATION"))
sess.connect(sess.root, s_get("HTTP HEADER CACHECONTROL"))
sess.connect(sess.root, s_get("HTTP HEADER CLOSE"))
sess.connect(sess.root, s_get("HTTP HEADER CONTENTLENGTH"))
sess.connect(sess.root, s_get("HTTP HEADER CONTENTMD5"))
sess.connect(sess.root, s_get("HTTP HEADER COOKIE"))
sess.connect(sess.root, s_get("HTTP HEADER DATE"))
sess.connect(sess.root, s_get("HTTP HEADER DNT"))
sess.connect(sess.root, s_get("HTTP HEADER EXPECT"))
sess.connect(sess.root, s_get("HTTP HEADER FROM"))
sess.connect(sess.root, s_get("HTTP HEADER HOST"))
sess.connect(sess.root, s_get("HTTP HEADER IFMATCH"))
sess.connect(sess.root, s_get("HTTP HEADER IFMODIFIEDSINCE"))
sess.connect(sess.root, s_get("HTTP HEADER IFNONEMATCH"))
sess.connect(sess.root, s_get("HTTP HEADER IFRANGE"))
sess.connect(sess.root, s_get("HTTP HEADER IFUNMODIFIEDSINCE"))
sess.connect(sess.root, s_get("HTTP HEADER KEEPALIVE"))
sess.connect(sess.root, s_get("HTTP HEADER MAXFORWARDS"))
sess.connect(sess.root, s_get("HTTP HEADER PRAGMA"))
sess.connect(sess.root, s_get("HTTP HEADER PROXYAUTHORIZATION"))
sess.connect(sess.root, s_get("HTTP HEADER RANGE"))
sess.connect(sess.root, s_get("HTTP HEADER REFERER"))
sess.connect(sess.root, s_get("HTTP HEADER TE"))
sess.connect(sess.root, s_get("HTTP HEADER UPGRADE"))
sess.connect(sess.root, s_get("HTTP HEADER USERAGENT"))
sess.connect(sess.root, s_get("HTTP HEADER VIA"))
sess.connect(sess.root, s_get("HTTP HEADER WARNING"))
sess.connect(sess.root, s_get("HTTP HEADER XATTDEVICEID"))
sess.connect(sess.root, s_get("HTTP HEADER XDONOTTRACK"))
sess.connect(sess.root, s_get("HTTP HEADER XFORWARDEDFOR"))
sess.connect(sess.root, s_get("HTTP HEADER XREQUESTEDWITH"))
sess.connect(sess.root, s_get("HTTP HEADER XWAPPROFILE"))
'''
'''
print("session imported post requests")
sess.connect(sess.root, s_get("HTTP VERBS POST"))
sess.connect(sess.root, s_get("HTTP VERBS POST ALL"))
sess.connect(sess.root, s_get("HTTP VERBS POST REQ"))
'''
sess.fuzz()
