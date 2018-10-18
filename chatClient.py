# -*- coding: utf-8 -*-

import os
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
history = open('history.html', 'w')

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
			return ('<font color="gray">' + name + '(' + ip + ') speaks to you quietly at ' \
				+ nowTime + ' :</font><br><font color="black">' + cmd + '</font>')
		else:
			ret = ''
			opt = cmd.split(' ')
			if opt[0] == '/login':
				if opt[1] == 'true':
					ret = 'Logged in!'
				elif opt[1] == 'false':
					ret = 'Authentication failed. Please check your information and try again.'
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
			if re.search(IPpattern, msg[0]):
				print('Invalid username.')
				return 'NameErr'
			elif len(msg[0]) > 20:
				msg[0] = msg[0][:20]
			msg = '/login ' + msg[0] + ' ' + msg[1]
		elif msg[:12] == '/setPassword':
			msg = msg[13:].split(' ')
			if len(msg) > 2:
				print('Invalid password.')
				return 'PwErr'
			msg = '/setPassword ' + hashlib.md5(msg[0].encode('utf-8')).hexdigest() + ' ' \
			+ hashlib.md5(msg[1].encode('utf-8')).hexdigest()
		elif msg[:8] == '/setName':
			msg = msg[9:]
			if ' ' in msg or re.search(IPpattern, msg):
				print('Invalid name.')
				return 'NameErr'
			elif len(msg) > 20:
				msg = msg[:20]
			msg = '/setName ' + msg
		try:
			s.send(msg.encode('GBK'))
		except ConnectionResetError:
			print('Cannot connect to the server.')
			return 'ConErr'

	def receive(self):
		try:
			msg = s.recv(1024).decode('GBK')
		except ConnectionResetError:
			print('Cannot connect to the server.')
			time.sleep(5)
			try:
				processText.connect(host, port)
			except ConnectionRefusedError:
				pass
			except TimeoutError:
				pass
			except OSError:
				pass
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
			else:
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
		self.actionHelp = QtWidgets.QAction(MainWindow)
		self.actionHelp.setObjectName("actionHelp")
		self.actionAbout = QtWidgets.QAction(MainWindow)
		self.actionAbout.setObjectName("actionAbout")
		self.actionUpdate = QtWidgets.QAction(MainWindow)
		self.actionUpdate.setObjectName("actionUpdate")
		self.menuAbout.addAction(self.actionHelp)
		self.menuAbout.addSeparator()
		self.menuAbout.addAction(self.actionUpdate)
		self.menuAbout.addAction(self.actionAbout)
		self.menubar.addAction(self.menuAbout.menuAction())

		self.actionAbout.triggered.connect(self.showAbout)
		self.actionHelp.triggered.connect(self.showHelp)
		self.actionUpdate.triggered.connect(self.checkForUpdates)

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
		self.menuAbout.setTitle(_translate("MainWindow", "Help"))
		self.actionHelp.setText(_translate("MainWindow", "Help"))
		self.actionUpdate.setText(_translate("MainWindow", "Check for Updates..."))
		self.actionAbout.setText(_translate("MainWindow", "About"))

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
		global host
		global port
		self.statusbar.showMessage('Connected to ' + host + ':' + str(port))
	
	def sendStatus(self):
		nowTime = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')
		self.statusbar.showMessage('Sent at ' + nowTime)

	def sendMessage(self):
		message = self.TextArea.toPlainText()
		err = processText.send(processText, message)
		if err == 'PwErr':
			self.showMessage('Invalid password.')
		elif err == 'NameErr':
			self.showMessage('Invalid name.')
		elif err == 'ConErr':
			self.showMessage('Cannot connect to the server.')
		else:
			self.TextArea.clear()

	def updateText(self, message):
		message = self.parseCmd(message)
		self.textBrowser.append(message)
		print(message + '<br>', file = history)
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

	def showAbout(self):
		QtWidgets.QMessageBox.about(self, 'About', 
			'''LAN Chat Client made by <a href="https://www.hawa130.xyz/">hawa130</a>.
			<center><a href="https://github.com/hawa130/LANChatClient">GitHub</a></center>''')

	def showHelp(self):
		QtWidgets.QMessageBox.about(self, 'Help', 
			'''<pre>/setName [NewName]</pre> Reset your name.<br>
			<pre>/sendto [Name] [Message]</pre> Send a message to a designated user.<br>
			<center><a href="https://github.com/hawa130/LANChatClient/blob/master/README.md">Online Documentation</a></center>''')

	def checkForUpdates(self):
		QtGui.QDesktopServices.openUrl(QtCore.QUrl('https://github.com/hawa130/LANChatClient/releases'))

	def showMessage(self, msg):
		QtWidgets.QMessageBox.information(self, 'Something went wrong...', msg)

class Ui_LoginDialog(object):
	def setupUi(self, LoginDialog):
		LoginDialog.setObjectName("LoginDialog")
		LoginDialog.resize(325, 196)
		font = QtGui.QFont()
		font.setFamily("微软雅黑")
		font.setBold(False)
		font.setWeight(50)
		LoginDialog.setFont(font)
		self.gridLayout = QtWidgets.QGridLayout(LoginDialog)
		self.gridLayout.setObjectName("gridLayout")
		self.horizontalLayout = QtWidgets.QHBoxLayout()
		self.horizontalLayout.setObjectName("horizontalLayout")
		self.labelIP = QtWidgets.QLabel(LoginDialog)
		self.labelIP.setObjectName("labelIP")
		self.horizontalLayout.addWidget(self.labelIP)
		self.IPEdit = QtWidgets.QLineEdit(LoginDialog)
		self.IPEdit.setFocusPolicy(QtCore.Qt.StrongFocus)
		self.IPEdit.setObjectName("IPEdit")
		self.horizontalLayout.addWidget(self.IPEdit)
		self.labelPort = QtWidgets.QLabel(LoginDialog)
		self.labelPort.setObjectName("labelPort")
		self.horizontalLayout.addWidget(self.labelPort)
		self.spinBox = QtWidgets.QSpinBox(LoginDialog)
		self.spinBox.setMaximum(65535)
		self.spinBox.setProperty("value", 8889)
		self.spinBox.setObjectName("spinBox")
		self.horizontalLayout.addWidget(self.spinBox)
		self.gridLayout.addLayout(self.horizontalLayout, 2, 1, 1, 2)
		spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
		self.gridLayout.addItem(spacerItem, 4, 0, 1, 1)
		self.PwEdit = QtWidgets.QLineEdit(LoginDialog)
		self.PwEdit.setEchoMode(QtWidgets.QLineEdit.Password)
		self.PwEdit.setObjectName("PwEdit")
		self.gridLayout.addWidget(self.PwEdit, 5, 2, 1, 1)
		spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
		self.gridLayout.addItem(spacerItem1, 4, 3, 1, 1)
		spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
		self.gridLayout.addItem(spacerItem2, 5, 0, 1, 1)
		self.LabelName = QtWidgets.QLabel(LoginDialog)
		self.LabelName.setObjectName("LabelName")
		self.gridLayout.addWidget(self.LabelName, 4, 1, 1, 1)
		spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
		self.gridLayout.addItem(spacerItem3, 5, 3, 1, 1)
		self.NameEdit = QtWidgets.QLineEdit(LoginDialog)
		self.NameEdit.setObjectName("NameEdit")
		self.gridLayout.addWidget(self.NameEdit, 4, 2, 1, 1)
		self.buttonBox = QtWidgets.QDialogButtonBox(LoginDialog)
		self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
		self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
		self.buttonBox.setObjectName("buttonBox")
		self.gridLayout.addWidget(self.buttonBox, 8, 2, 1, 1)
		spacerItem4 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
		self.gridLayout.addItem(spacerItem4, 7, 2, 1, 1)
		self.labelPw = QtWidgets.QLabel(LoginDialog)
		self.labelPw.setObjectName("labelPw")
		self.gridLayout.addWidget(self.labelPw, 5, 1, 1, 1)
		spacerItem5 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
		self.gridLayout.addItem(spacerItem5, 0, 2, 1, 1)
		spacerItem6 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
		self.gridLayout.addItem(spacerItem6, 3, 2, 1, 1)
		spacerItem7 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
		self.gridLayout.addItem(spacerItem7, 2, 3, 1, 1)
		spacerItem8 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
		self.gridLayout.addItem(spacerItem8, 2, 0, 1, 1)
		self.checkBox = QtWidgets.QCheckBox(LoginDialog)
		self.checkBox.setObjectName("checkBox")
		self.gridLayout.addWidget(self.checkBox, 6, 2, 1, 1)
		self.buttonBox.raise_()
		self.PwEdit.raise_()
		self.LabelName.raise_()
		self.labelPw.raise_()
		self.NameEdit.raise_()
		self.checkBox.raise_()

		self.retranslateUi(LoginDialog)
		self.buttonBox.accepted.connect(self.login)
		self.buttonBox.rejected.connect(LoginDialog.reject)
		self.checkBox.stateChanged.connect(self.remInfo)
		self.NameEdit.returnPressed.connect(self.PwEdit.setFocus)

		QtCore.QMetaObject.connectSlotsByName(LoginDialog)
		LoginDialog.setTabOrder(self.IPEdit, self.spinBox)
		LoginDialog.setTabOrder(self.spinBox, self.NameEdit)
		LoginDialog.setTabOrder(self.NameEdit, self.PwEdit)
		LoginDialog.setTabOrder(self.PwEdit, self.checkBox)

	def retranslateUi(self, LoginDialog):
		_translate = QtCore.QCoreApplication.translate
		LoginDialog.setWindowTitle(_translate("LoginDialog", "Log in"))
		self.labelIP.setText(_translate("LoginDialog", "IP"))
		self.labelPort.setText(_translate("LoginDialog", "Port"))
		self.LabelName.setText(_translate("LoginDialog", "Username"))
		self.labelPw.setText(_translate("LoginDialog", "Password"))
		self.checkBox.setText(_translate("LoginDialog", "Remember me"))

class iLoginDialog(QtWidgets.QDialog, Ui_LoginDialog):
	flag = False
	read = False
	host = '127.0.0.1'
	port = 8889
	name = ''
	password = ''
	def __init__(self):
		super(iLoginDialog, self).__init__()
		self.setupUi(self)
		try:
			saved = open('savedinfo')
		except FileNotFoundError:
			pass
		else:
			self.read = True
			self.flag = True
			self.checkBox.toggle()
			self.host = saved.readline().replace('\n', '')
			self.IPEdit.setText(self.host)
			self.port = int(saved.readline())
			self.spinBox.setValue(self.port)
			self.name = saved.readline().replace('\n', '')
			self.NameEdit.setText(self.name)
			self.password = saved.readline().replace('\n', '')
			self.PwEdit.setText(self.password)
		self.NameEdit.textChanged.connect(self.removeSaved)
		self.PwEdit.textChanged.connect(self.removeSaved)
		
	def login(self):
		global host
		global port
		host = self.host = self.IPEdit.text()
		port = self.port = self.spinBox.value()
		self.name = self.NameEdit.text()
		self.password = self.PwEdit.text()
		if not self.read:
			self.password = hashlib.md5(self.password.encode('utf-8')).hexdigest()
		if self.flag:
			saved = open('savedinfo','w')
			print(self.host, file = saved)
			print(self.port, file = saved)
			print(self.name, file = saved)
			print(self.password, file = saved)
			saved.close()
		else:
			try:
				os.remove('savedinfo')
			except FileNotFoundError:
				pass
		if ' ' in self.password or ' ' in self.name:
			print('Invalid password or name.')
			self.showMessage('Invalid password or name.')
			return
		try:
			processText.connect(self.host, self.port)
		except ConnectionRefusedError:
			print('Cannot connect to the server.')
			self.showMessage('Cannot connect to the server.')
		except TimeoutError:
			print('Connection time out.')
			self.showMessage('Connection time out.')
		except OSError:
			print('Cannot connect to the server. Please check your IP address.')
			self.showMessage('Cannot connect to the server.<br>Please check your IP address.')
		else:
			if processText.send(processText, '/login ' + self.name + ' ' + self.password) == 'NameErr':
				print('Invalid username.')
				self.showMessage('Invalid username.')
			msg = processText.receive(processText)
			print(msg)
			if msg == '<i><font color="gray">Logged in!</font></i>':
				self.accept()
			else:
				self.showMessage('Authentication failed. Please check your information and try again.')
				return

	def remInfo(self, state):
		if state == QtCore.Qt.Checked:
			self.flag = True
		else:
			self.flag = False

	def showMessage(self, msg):
		QtWidgets.QMessageBox.information(self, 'Something went wrong...', msg)

	def removeSaved(self, string):
		self.read = False

def login():
	if iLoginDialog().exec_():
		return True
	return False

if __name__ == '__main__':
	myaddr = socket.gethostbyname(socket.gethostname())
	mainApp = QtWidgets.QApplication(sys.argv)
	mainApp.setStyle('Fusion')
	if login():
		widget = Window()
		widget.show()
		sys.exit(mainApp.exec_())
