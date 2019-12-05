import os
import socket
import struct
import binascii
import numpy as np
import pandas as pd
from ipaddress import *
from scapy.all import *
import tensorflow as tf
import matplotlib.pyplot as plt
from optparse import OptionParser
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

parser = OptionParser(usage="Usage: %prog -i interface -p IPaddr -m MACaddr -n netmask",version="%prog 1.0")
parser.add_option("-i", "--interface",dest="interface", default=None, help="Interface Name", type="str")
parser.add_option("-p", "--ip",dest="my_ip", default=None, help="Machine's IP address", type="str")
parser.add_option("-m", "--mac",dest="my_mac", default=None, help="Machine's MAC address", type="str")
parser.add_option("-n", "--netmask",dest="netmask", default=None, help="Network Mask (Ex: 255.255.255.0)", type="str")
(options, args) = parser.parse_args()

ATTACK_CATEGORIES = ['ICMP Smurf Attack', 'Ping of Death', 'Normal Ping']
interface, my_ip, my_mac, netmask = options.interface, options.my_ip, options.my_mac, options.netmask
labelencoder_X_0, labelencoder_X_1, labelencoder_X_2, labelencoder_X_3 = LabelEncoder(), LabelEncoder(), LabelEncoder(), LabelEncoder()
dataset, X, Y = None, None, None
sc = StandardScaler()

attack_prediction_model = tf.keras.models.Sequential()
attack_prediction_model.add(tf.keras.layers.Flatten())
attack_prediction_model.add(tf.keras.layers.Dense(64, activation=tf.nn.relu))
attack_prediction_model.add(tf.keras.layers.Dense(16, activation=tf.nn.relu))
attack_prediction_model.add(tf.keras.layers.Dense(64, activation=tf.nn.relu))
attack_prediction_model.add(tf.keras.layers.Dense(16, activation=tf.nn.relu))
attack_prediction_model.add(tf.keras.layers.Dense(3, activation=tf.nn.softmax))
attack_prediction_model.compile(optimizer='adam',
		loss='sparse_categorical_crossentropy',
		metrics=['accuracy'])

if not interface:
	interface = conf.iface
if not my_ip:
	my_ip = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0'][0]
if not my_mac:
	my_mac = get_if_hwaddr(interface)
if not netmask:
	for x in conf.route.routes:
		if x[3]==interface and x[4]==my_ip and x[2]=='0.0.0.0':
			if IPv4Address(x[1]).compressed.endswith(".0") and IPv4Address(x[0]).compressed.endswith(".0"):
				netmask = IPv4Address(x[1]).compressed
icmp_count, ping_count, pod_count = 0, 0, 0

fp = open('capture-{}.csv'.format(my_mac), 'w')
fp.close()

def log_this(msg):
	fp = open('capture-{}.csv'.format(my_mac), 'a')
	fp.write(msg+"\n")
	fp.close()

def clear():
	os.system('clear')

def display(recent_activities):
	clear()
	msg = ""
	for activity in recent_activities[::-1]:
		msg+=activity+"\n"
	banner = '''
[i] Total Ping Requests: {}
[i] Ping of Death: {}

[i] Recent Activities:

{}

[i] Total ICMP Smurf Requests: {}
[i] ICMP Smurf Attack: {}
'''.format(ping_count,
	pod_count>5 or ping_count>10,
	msg,
	icmp_count,
	icmp_count>5,)
	print(banner)

def AI_display(recent_activities):
	clear()
	msg = ""
	for activity in recent_activities[::-1]:
		msg+=activity+"\n"
	dataset = pd.read_csv('capture-{}.csv'.format(my_mac))
	X = dataset.iloc[-1:, :5].values
	y = dataset.iloc[-1:, 5].values
	y = y[0]
	X[:, 0] = labelencoder_X_0.fit_transform(X[:, 0])
	X[:, 1] = labelencoder_X_1.fit_transform(X[:, 1])
	X[:, 2] = labelencoder_X_2.fit_transform(X[:, 2])
	X[:, 3] = labelencoder_X_3.fit_transform(X[:, 3])
	X = X.astype(int)
	X = sc.transform(X)
	y_pred = attack_prediction_model.predict(X)[0]
	y_pred_value = np.argmax(y_pred)
	banner = '''
[i] Total Ping Requests: {}
[i] Total ICMP Smurf Requests: {}

[i] Recent Activities:

{}

## [ ATTACK PREDICTION NEURAL NETWORK ] ##

	{} --> [{}]
'''.format(ping_count, icmp_count, msg, recent_activities[-1:][0], "Potential "+ATTACK_CATEGORIES[y_pred_value])
	print(banner)

def train_AI():
	clear()
	print("[i] Training the AI..")
	dataset = pd.read_csv('capture-{}.csv'.format(my_mac))
	X = dataset.iloc[:, :5].values
	y = dataset.iloc[:, 5].values
	X[:, 0] = labelencoder_X_0.fit_transform(X[:, 0])
	X[:, 1] = labelencoder_X_1.fit_transform(X[:, 1])
	X[:, 2] = labelencoder_X_2.fit_transform(X[:, 2])
	X[:, 3] = labelencoder_X_3.fit_transform(X[:, 3])
	X = X.astype(int)
	X = sc.fit_transform(X)
	attack_prediction_model.fit(X, y, epochs=10)
	clear()

def analyze(pkt):
	global recent_activities
	global ping_count
	global icmp_count
	if len(recent_activities)>10:
		recent_activities = recent_activities[-10:]
	dest_mac = pkt[0][Ether].dst
	src_mac = pkt[0][Ether].src
	src_ip = pkt[0][IP].src
	dest_ip = pkt[0][IP].dst
	pkt_size = len(pkt[0][Raw].load)
	recent_activities.append("{} [{}] --> {} [{}] ({} bytes)".format(src_ip, src_mac, dest_ip, dest_mac, pkt_size))
	if src_ip == my_ip and src_mac != my_mac:
		icmp_count+=1
		log_this("{},{},{},{},{},{}".format(src_ip, src_mac, dest_ip, dest_mac, pkt_size, 0))
	if dest_mac == my_mac:
		ping_count+=1
		if pkt_size>1024:
			log_this("{},{},{},{},{},{}".format(src_ip, src_mac, dest_ip, dest_mac, pkt_size, 1))
		else:
			log_this("{},{},{},{},{},{}".format(src_ip, src_mac, dest_ip, dest_mac, pkt_size, 2))
	if len(open('capture-{}.csv'.format(my_mac),'r').readlines())%100 == 0:
		train_AI()
	elif len(open('capture-{}.csv'.format(my_mac),'r').readlines())>100:
		AI_display(recent_activities)
	else:
		display(recent_activities)

recent_activities = []
while True:
	try:
		sniff(iface=interface, filter="icmp", prn=analyze)
	except Exception as e:
		print("[-] ERROR !!")
		print(e)
		sys.exit("\n[-] Shutting Down..")