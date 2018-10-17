# -*- coding: utf-8 -*-

import re
import sys
import time
import socket
import hashlib
import datetime
from PyQt5 import sip
from PyQt5 import QtCore, QtGui, QtWidgets

global host
global port
global myaddr

s = socket.socket()
dic = {}
IPpattern = r'\(((25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\)'

class processText(object):
	def __init__(self):
		super(processText, self).__init__()
		self.arg = arg

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
			cmd = cmd.replace('&', '&amp;')
			cmd = cmd.replace('>', '&gt;')
			cmd = cmd.replace('<', '&lt;')
			cmd = cmd.replace('"','&quot;')
			cmd = cmd.replace("'",'&#39;')
			cmd = cmd.replace(' ','&nbsp;')
			cmd = cmd.replace('\n','<br>')
			cmd = cmd.replace('\r','<br>')
			try:
				name = dic[ip]
			except KeyError:
				name = ip
			nowTime = datetime.datetime.now().strftime('%H:%M:%S')
			return ('<font color="gray">' + name + '(' + ip + ') speaks to you quietly at ' + nowTime + ' :</font><br><font color="black">' + cmd + '</font>')
		else:
			opt = cmd.split(' ')
			if opt[0] == '/login':
				if opt[1] == 'true':
					ret = 'Logged in!'
				elif opt[1] == 'false':
					ret = 'Failed. Please check your information and try again.'
			elif opt[0] == '/admin':
				if opt[1] == 'true':
					ret = 'Logged in as administrator.'
				elif opt[1] == 'false':
					ret = 'Failed.'
			elif opt[0] == '/newUser' or opt[0] == '/changeName' or opt[0] == '/delUser':
				return cmd
		return '<i><font color="gray">' + ret + '</font></i>'

	def parseText(msg):
		msg = msg[6:]
		ip = msg.split(' ')[0]
		msg = msg.replace(ip + ' ', '', 1)
		msg = msg.replace('&', '&amp;')
		msg = msg.replace('>', '&gt;')
		msg = msg.replace('<', '&lt;')
		msg = msg.replace('"','&quot;')
		msg = msg.replace("'",'&#39;')
		msg = msg.replace(' ','&nbsp;')
		msg = msg.replace('\n','<br>')
		msg = msg.replace('\r','<br>')
		try:
			name = dic[ip]
		except KeyError:
			name = ip
		nowTime = datetime.datetime.now().strftime('%H:%M:%S')
		if ip == myaddr:
			return ('<font color="green">' + name + '(' + ip + ') ' + nowTime + '</font><br>' + msg)
		return ('<font color="blue">' + name + '(' + ip + ') ' + nowTime + '</font><br>' + msg)

	def connect(host, port):
		s.connect((host, port))
		nowTime = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')
		print('Connected to ' + host + ':' + str(port) + ' at ' + nowTime)

	def send(self, msg):
		if msg == '':
			return
		if msg == '/quit':
			s.close()
		if not self.isCmd(msg):
			msg = '/text ' + msg
		elif msg[:6] == '/login':
			msg = msg[7:].split(' ')
			password = hashlib.md5(msg[1].encode('utf-8')).hexdigest()
			msg = '/login ' + msg[0] + ' ' + password
		elif msg[:12] == '/setPassword':
			msg = '/setPassword ' + hashlib.md5(msg[13:].encode('utf-8')).hexdigest()
		elif msg[:8] == '/setName':
			msg = msg[9:]
			if re.search(IPpattern, msg):
				return
			elif len(msg) > 20:
				msg = msg[:20]
			msg = '/setName ' + msg
		try:
			s.send(msg.encode('GBK'))
		except ConnectionResetError:
			print('Cannot connect to the server.')

	def receive(self):
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
			return self.parseText(msg)
		for msg in data:
			if msg[:7] == '/server':
				nowTime = datetime.datetime.now().strftime('%H:%M:%S')
				return ('<b><font color="gray">Server ' + nowTime + '</font></b><br>' + msg[8:])
			elif msg[0] == '/':
				return self.parseCmd(msg)

class MyThread(QtCore.QThread):
	trigger = QtCore.pyqtSignal(str)

	def __init__(self, parent = None):
		super(MyThread, self).__init__(parent)

	def run(self):
		while True:
			message = processText.receive(processText)
			self.trigger.emit(message)

class Ui_MainWindow(object):
	def setupUi(self, MainWindow):
		MainWindow.setObjectName("MainWindow")
		MainWindow.resize(691, 509)
		font = QtGui.QFont()
		font.setFamily("微软雅黑")
		MainWindow.setFont(font)
		MainWindow.setStatusTip("")
		MainWindow.setWhatsThis("")
		MainWindow.setAccessibleName("")
		MainWindow.setAccessibleDescription("")
		self.centralwidget = QtWidgets.QWidget(MainWindow)
		self.centralwidget.setObjectName("centralwidget")
		self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
		self.gridLayout.setObjectName("gridLayout")
		self.splitter_3 = QtWidgets.QSplitter(self.centralwidget)
		self.splitter_3.setOrientation(QtCore.Qt.Vertical)
		self.splitter_3.setObjectName("splitter_3")
		self.splitter_2 = QtWidgets.QSplitter(self.splitter_3)
		self.splitter_2.setOrientation(QtCore.Qt.Horizontal)
		self.splitter_2.setObjectName("splitter_2")
		self.textBrowser = QtWidgets.QTextBrowser(self.splitter_2)
		font = QtGui.QFont()
		font.setFamily("微软雅黑")
		self.textBrowser.setFont(font)
		self.textBrowser.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
		self.textBrowser.setObjectName("textBrowser")
		self.IPlist = QtWidgets.QListWidget(self.splitter_2)
		sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
		sizePolicy.setHorizontalStretch(0)
		sizePolicy.setVerticalStretch(0)
		sizePolicy.setHeightForWidth(self.IPlist.sizePolicy().hasHeightForWidth())
		self.IPlist.setSizePolicy(sizePolicy)
		self.IPlist.setMinimumSize(QtCore.QSize(0, 0))
		self.IPlist.setMaximumSize(QtCore.QSize(170, 16777215))
		self.IPlist.setBaseSize(QtCore.QSize(0, 0))
		self.IPlist.setObjectName("IPlist")
		self.splitter = QtWidgets.QSplitter(self.splitter_3)
		self.splitter.setOrientation(QtCore.Qt.Horizontal)
		self.splitter.setObjectName("splitter")
		self.TextArea = QtWidgets.QTextEdit(self.splitter)
		sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
		sizePolicy.setHorizontalStretch(0)
		sizePolicy.setVerticalStretch(0)
		sizePolicy.setHeightForWidth(self.TextArea.sizePolicy().hasHeightForWidth())
		self.TextArea.setSizePolicy(sizePolicy)
		self.TextArea.setMinimumSize(QtCore.QSize(0, 0))
		self.TextArea.setMaximumSize(QtCore.QSize(16777215, 90))
		self.TextArea.setBaseSize(QtCore.QSize(0, 0))
		self.TextArea.setPlainText("")
		self.TextArea.setOverwriteMode(False)
		self.TextArea.setObjectName("TextArea")
		self.sendButton = QtWidgets.QPushButton(self.splitter)
		self.sendButton.setMaximumSize(QtCore.QSize(100, 16777215))
		self.sendButton.setObjectName("sendButton")
		self.gridLayout.addWidget(self.splitter_3, 0, 0, 1, 1)
		MainWindow.setCentralWidget(self.centralwidget)
		self.menubar = QtWidgets.QMenuBar(MainWindow)
		self.menubar.setGeometry(QtCore.QRect(0, 0, 691, 23))
		self.menubar.setObjectName("menubar")
		self.menuAbout = QtWidgets.QMenu(self.menubar)
		self.menuAbout.setObjectName("menuAbout")
		MainWindow.setMenuBar(self.menubar)
		self.statusbar = QtWidgets.QStatusBar(MainWindow)
		self.statusbar.setObjectName("statusbar")
		MainWindow.setStatusBar(self.statusbar)
		self.actionAbout = QtWidgets.QAction(MainWindow)
		self.actionAbout.setObjectName("actionAbout")
		self.actionHelp = QtWidgets.QAction(MainWindow)
		self.actionHelp.setObjectName("actionHelp")
		self.menuAbout.addAction(self.actionAbout)
		self.menuAbout.addSeparator()
		self.menuAbout.addAction(self.actionHelp)
		self.menubar.addAction(self.menuAbout.menuAction())

		self.retranslateUi(MainWindow)
		self.sendButton.clicked.connect(self.TextArea.setFocus)
		self.sendButton.clicked.connect(self.sendMessage)
		self.sendButton.clicked.connect(MainWindow.sendStatus)
		self.TextArea.cursorPositionChanged.connect(MainWindow.initStatusbar)
		QtCore.QMetaObject.connectSlotsByName(MainWindow)
		MainWindow.setTabOrder(self.TextArea, self.sendButton)
		MainWindow.setTabOrder(self.sendButton, self.textBrowser)
		MainWindow.setTabOrder(self.textBrowser, self.IPlist)

		self.initStatusbar()
		self.IPlist.itemDoubleClicked.connect(self.selectIP)
		self.threads = MyThread(self)
		self.threads.trigger.connect(self.updateText)
		self.threads.start()

	def retranslateUi(self, MainWindow):
		_translate = QtCore.QCoreApplication.translate
		MainWindow.setWindowTitle(_translate("MainWindow", "Chat Client"))
		self.sendButton.setText(_translate("MainWindow", "Send"))
		self.menuAbout.setTitle(_translate("MainWindow", "About"))
		self.actionAbout.setText(_translate("MainWindow", "About"))
		self.actionHelp.setText(_translate("MainWindow", "Help"))

class Window(QtWidgets.QMainWindow, Ui_MainWindow):
	def __init__(self):
		super(Window, self).__init__()
		self.setupUi(self)

	def parseCmd(self, cmd):
		opt = cmd.split(' ')
		if opt[0] == '/newUser':
			dic[opt[1]] = opt[2]
			self.addToList(opt[2] + '(' + opt[1] + ')')
			ret = 'User ' + opt[2] + '(' + opt[1] + ')' + ' joined in the chatting.'
			return '<font color="gray">' + ret + '</font>'
		elif opt[0] == '/changeName':
			try:
				oldName = dic[opt[1]]
			except KeyError:
				oldName = opt[1]
			self.updateList(oldName + '(' + opt[1] + ')', opt[2] + '(' + opt[1] + ')')
			ret = ('User ' + oldName + '(' + opt[1] + ')' + ' has changed the name into ' + opt[2] + '.')
			dic[opt[1]] = opt[2]
			return '<font color="gray">' + ret + '</font>'
		elif opt[0] == '/delUser':
			try:
				name = dic[opt[1]]
			except KeyError:
				ret = 'User ' + opt[1] + ' quitted the chatting.'
			else:
				ret = 'User ' + name + '(' + opt[1] + ') quitted the chatting.'
				del dic[opt[1]]
			self.delFromList(name + '(' + opt[1] + ')')
			return '<font color="gray">' + ret + '</font>'
		else:
			return cmd

	def selectIP(self, item):
		ip = item.text()
		ip = re.sub(IPpattern, '', ip)
		self.TextArea.append('/sendto ' + ip + ' ')
		self.TextArea.setFocus()
	
	def initStatusbar(self):
		self.statusbar.showMessage('Connected to ' + host + ':' + str(port))
	
	def sendStatus(self):
		nowTime = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')
		self.statusbar.showMessage('Sent at ' + nowTime)

	def sendMessage(self):
		message = self.TextArea.toPlainText()
		processText.send(processText, message)
		self.TextArea.clear()

	def updateText(self, message):
		message = self.parseCmd(message)
		self.textBrowser.append(message)
		print(message)
		self.textBrowser.moveCursor(QtGui.QTextCursor.End)

	def keyPressEvent(self, event):
		if str(event.key() == '16777249'):
			if str(event.key()) == '16777221' or str(event.key()) == '16777220':
				self.sendMessage()
				self.sendStatus()

	def addToList(self, item):
		self.IPlist.addItem(item)

	def delFromList(self, string):
		items = self.IPlist.findItems(string, QtCore.Qt.MatchExactly)
		for item in items:
			self.IPlist.takeItem(self.IPlist.row(item))

	def updateList(self, old, new):
		items = self.IPlist.findItems(old, QtCore.Qt.MatchExactly)
		for item in items:
			item.setText(new)

if __name__ == '__main__':
	host = input('Input IP address: ')
	#host = '172.16.42.32'
	myaddr = socket.gethostbyname(socket.gethostname())
	port = 8889
	dic[host] = 'Server'
	dic['127.0.0.1'] = 'Server'
	try:
		processText.connect(host, port)
	except ConnectionRefusedError:
		print('Cannot connect to the server.')
	except TimeoutError:
		print('Connection time out.')
	except OSError:
		print('Invalid operation.')
	else:
		app = QtWidgets.QApplication(sys.argv)
		app.setStyle('Fusion')
		widget = Window()
		widget.show()
		sys.exit(app.exec_())
