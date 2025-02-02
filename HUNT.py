import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QWidget, QLineEdit, QCheckBox
from PyQt5.QtCore import Qt
from scapy.all import ARP, Ether, srp
import nmap
import requests
import sqlite3
import matplotlib.pyplot as plt
from PIL import Image, ImageTk
import pyshark
import psutil
from sklearn.ensemble import IsolationForest
import plotly.express as px
from sqlalchemy import create_engine, Column, String, Integer, Base
from cryptography.fernet import Fernet
from flask import Flask, jsonify, request
import asyncio
import schedule
import threading
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import smtplib
from email.mime.text import MIMEText

# Database setup
engine = create_engine('sqlite:///scan_results.db')
Base = declarative_base()

class ScanResult(Base):
    __tablename__ = 'results'
    id = Column(Integer, primary_key=True)
    ip = Column(String)
    mac = Column(String)
    
Base.metadata.create_all(engine)

# Flask API setup
app = Flask(__name__)

@app.route('/scan', methods=['GET'])
def api_scan():
    result = scan_network()
    return jsonify(result)

# Slack notification function
def send_slack_notification(message):
    client = WebClient(token="your-slack-bot-token")
    try:
        response = client.chat_postMessage(channel="#general", text=message)
    except SlackApiError as e:
        print(f"Error sending message: {e.response['error']}")

# Email notification function
def send_email_notification(subject, message):
    sender_email = "your-email@example.com"
    receiver_email = "recipient@example.com"
    password = "your-email-password"

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
    except Exception as e:
        print(f"Error sending email: {e}")

# Function to handle login (using PyQt5)
class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('Login')
        self.setGeometry(100, 100, 300, 200)
        
        layout = QVBoxLayout()
        
        self.username_label = QLabel('Username:', self)
        layout.addWidget(self.username_label)
        self.username_entry = QLineEdit(self)
        layout.addWidget(self.username_entry)
        
        self.password_label = QLabel('Password:', self)
        layout.addWidget(self.password_label)
        self.password_entry = QLineEdit(self)
        self.password_entry.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_entry)
        
        self.login_button = QPushButton('Login', self)
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        
    def login(self):
        if self.username_entry.text() == 'admin' and self.password_entry.text() == 'password':
            self.close()
            self.main_window = MainWindow()
            self.main_window.show()
        else:
            QMessageBox.critical(self, 'Error', 'Invalid credentials')

# Function to display the main window (using PyQt5)
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('HUNT')
        self.setGeometry(100, 100, 600, 400)
        
        layout = QVBoxLayout()
        
        self.credits_label = QLabel("Created by: KIRK\nCreation Date: 2025-02-01\nProgram Details: Scanning local networks for IP and DVR cameras", self)
        layout.addWidget(self.credits_label)
        
        self.hunt_button = QPushButton("HUNT", self)
        layout.addWidget(self.hunt_button)
        
        self.scan_button = QPushButton("SCAN", self)
        self.scan_button.clicked.connect(self.scan)
        layout.addWidget(self.scan_button)
        
        self.map_button = QPushButton("MAP", self)
        self.map_button.clicked.connect(self.map_network)
        layout.addWidget(self.map_button)
        
        self.report_button = QPushButton("REPORT", self)
        self.report_button.clicked.connect(self.generate_report)
        layout.addWidget(self.report_button)
        
        self.settings_button = QPushButton("SETTINGS", self)
        layout.addWidget(self.settings_button)
        
        self.dark_mode_checkbox = QCheckBox("Dark Mode", self)
        self.dark_mode_checkbox.stateChanged.connect(self.toggle_dark_mode)
        layout.addWidget(self.dark_mode_checkbox)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
    
    def toggle_dark_mode(self):
        if self.dark_mode_checkbox.isChecked():
            self.setStyleSheet("background-color: #2E2E2E; color: white;")
        else:
            self.setStyleSheet("")
    
    def scan(self):
        result = scan_network()
        send_slack_notification("Scan completed successfully")
        send_email_notification("Scan Completed", "The scan has been completed successfully.")
        scan_window = ScanResultsWindow(result)
        scan_window.show()
        
    def map_network(self):
        visualize_network_map()
        
    def generate_report(self):
        generate_network_report()

# Function to show scan results (using PyQt5)
class ScanResultsWindow(QMainWindow):
    def __init__(self, results):
        super().__init__()
        self.results = results
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('SCAN Results')
        self.setGeometry(100, 100, 600, 400)
        
        layout = QVBoxLayout()
        
        for device in self.results:
            device_label = QLabel(f"IP: {device['ip']}, MAC: {device['mac']}", self)
            layout.addWidget(device_label)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

# Real-time network scanning function
def scan_network():
    nm = nmap.PortScanner()
    target_ip = "192.168.1.0/24"
    nm.scan(hosts=target_ip, arguments='-sn')
    devices = nm.all_hosts()
    results = [{'ip': host, 'mac': nm[host]['addresses']['mac']} for host in devices if 'mac' in nm[host]['addresses']]
    return results

# Visualization of network map
def visualize_network_map():
    data = {'IP': ['192.168.1.1', '192.168.1.2'], 'MAC': ['00:11:22:33:44:55', '66:77:88:99:AA:BB']}
    df = pd.DataFrame(data)
    fig = px.scatter(df, x='IP', y='MAC', title='Network Map')
    fig.show()

# Generate network report
def generate_network_report():
    conn = sqlite3.connect('scan_results.db')
    df = pd.read_sql('SELECT * FROM results', conn)
    fig = px.histogram(df, x='ip', title='Network Report')
    fig.show()
    
# Multithreading for real-time monitoring
def start_monitoring():
    while True:
        process = psutil.Process()
        print(f"CPU Usage: {process.cpu_percent()}%")
        asyncio.sleep(5)

# Start Flask API
def start_api():
    app.run(host='0.0.0.0', port=5000)

# Schedule scans
def scheduled_scan():
    result = scan_network()
    print("Scheduled scan completed:", result)

schedule.every().day.at("00:00").do(scheduled_scan)

# Start multithreading
monitoring_thread = threading.Thread(target=start_monitoring)
monitoring_thread.start()

api_thread = threading.Thread(target=start_api)
api_thread.start()

# Start the application
if __name__ == '__main__':
    app = QApplication(sys.argv)
    login = LoginWindow()
    login.show()
    sys.exit(app.exec_())
