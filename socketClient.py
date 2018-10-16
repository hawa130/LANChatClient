import socket
import hashlib
import datetime
import threading

s = socket.socket()

dic = {}

def isCmd(msg):
	if msg[0] == '/':
		return True
	else:
		return False

def parseCmd(cmd):
	if cmd[:7] == '/sendby':
		cmd = cmd[8:]
		ip = cmd.split(' ')[0]
		cmd = cmd.replace(ip + ' ', '', 1)
		try:
			name = dic[ip]
		except KeyError:
			name = ip
		nowTime = datetime.datetime.now().strftime('%H:%M:%S')
		return (name + '(' + ip + ') speaks to you quietly at ' + nowTime + ':\n' + cmd)
	cmd = cmd.split(' ')
	if cmd[0] == '/login':
		if cmd[1] == 'true':
			return ('Logged in!')
		elif cmd[1] == 'false':
			return ('Failed. Please check your information and try again.')
	elif cmd[0] == '/admin':
		if cmd[1] == 'true':
			return ('Logged in as administrator.')
		elif cmd[1] == 'false':
			return ('Failed.')
	elif cmd[0] == '/newUser':
		dic[cmd[1]] = cmd[2]
		return ('User ' + cmd[2] + '(' + cmd[1] + ')' + ' joined in the chatting.')
	elif cmd[0] == '/changeName':
		try:
			oldName = dic[cmd[1]]
		except KeyError:
			oldName = cmd[1]
		ret = ('User ' + oldName + '(' + cmd[1] + ')' + ' has changed the name into ' + cmd[2] + '.')
		dic[cmd[1]] = cmd[2]
		return ret
	elif cmd[0] == '/delUser':
		ret = ('User ' + dic[cmd[1]] + '(' + cmd[1] + ') quitted the chatting.')
		del dic[cmd[1]]
		return ret

def parseText(msg):
	msg = msg[6:]
	ip = msg.split(' ')[0]
	msg = msg.replace(ip + ' ', '', 1)
	try:
		name = dic[ip]
	except KeyError:
		name = ip
	nowTime = datetime.datetime.now().strftime('%H:%M:%S')
	return (name + '(' + ip + ') ' + nowTime + '\n' + msg)

def connect(host, port):
	s.connect((host, port))
	nowTime = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')
	print('Connected to ' + host + ':' + str(port) + ' at ' + nowTime)

def send():
	msg = input()
	if msg == '':
		return
	if msg == '/quit':
		s.close()
	if not isCmd(msg):
		msg = '/text ' + msg
	elif msg[:6] == '/login':
		msg = msg[7:].split(' ')
		password = hashlib.md5(msg[1].encode('utf-8')).hexdigest()
		msg = '/login ' + msg[0] + ' ' + password
	elif msg[:12] == '/setPassword':
		msg = '/setPassword ' + hashlib.md5(msg[13:].encode('utf-8')).hexdigest()
	s.send(msg.encode('GBK'))

def receive():
	try:
		msg = s.recv(1024).decode('GBK')
	except ConnectionResetError:
		print('Cannot connect to the server.')
		time.sleep(5)
		return
	if msg == None:
		return
	data = msg.split('\n')
	if msg[:5] == '/text':
		return parseText(msg)
	for msg in data:
		if msg[:7] == '/server':
			nowTime = datetime.datetime.now().strftime('%H:%M:%S')
			return ('Server ' + nowTime + '\n' + msg[8:])
		else:
			return parseCmd(msg)
def sendMessage():
	while True:
		send()

def rec():
	while True:
		print(receive())

if __name__ == '__main__':
	localhost = socket.gethostname()
	#host = input('Input IP address:')
	host = '172.16.42.32'
	dic[host] = 'Server'
	try:
		connect(host, 8889)
	except ConnectionRefusedError:
		print('Cannot connect to the server.')
	except TimeoutError:
		print('Connection time out.')
	else:
		threadSend = threading.Thread(target = sendMessage)
		threadRecv = threading.Thread(target = rec)
		threadSend.start()
		threadRecv.start()
