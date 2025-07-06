from flask import Blueprint, render_template, request, jsonify
import json
from .nmap import caller, parser

api = Blueprint('main', __name__)

# Store last scan data
last_scan_results = []

@api.route('/')
def home():
    return render_template('index.html')

@api.route('/scan', methods=['GET', 'POST'])
def scan():
    global last_scan_results
    results = []
    if request.method == 'POST':
        target = request.form.get('target')
        options = request.form.getlist('options')

        xml_output = caller.run_nmap(target, options)
        results = parser.parse_nmap_xml(xml_output)

        last_scan_results = results  # store globally

    return render_template('scanning.html', results=results)

@api.route('/device/<ip>')
def device(ip):
    device_info = next((dev for dev in last_scan_results if dev['ip'] == ip), None)
    if not device_info:
        return f"<h1>Device with IP {ip} not found in last scan.</h1>", 404
    return render_template('device.html', device=device_info)

@api.route('/scan_ports', methods=['POST'])
def scan_ports():
    data = request.get_json()
    ip = data.get('ip')
    ports = data.get('ports')
    if not ip or not ports:
        return jsonify({"output": "Missing IP or ports"}), 400

    output = caller.run_custom_nmap(ip, ports)
    return jsonify({"output": output})
