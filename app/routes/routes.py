from flask import Blueprint, jsonify, render_template
from .nmap import caller
from .nmap import parser
from flask import request, jsonify

api = Blueprint('api', __name__)

@api.route('/api/data')
def get_data():
    return jsonify({"message": "Hello from the API!", "items": [1,2,3]})


@api.route('/')
def home():
    return render_template('index.html')

@api.route('/nmap', methods=['POST'])
def nmap_query():
    data = request.get_json()
    ip_range = data.get('ip_range')
    stdout = caller.run_nmap(ip_range)
    data = parser.parse_nmap_xml(stdout)
    return jsonify(statusCode= 200, data=data)
