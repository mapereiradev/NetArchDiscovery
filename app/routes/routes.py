from flask import Blueprint, jsonify, render_template
from .nmap import caller
from .nmap import parser
from flask import request, jsonify

api = Blueprint('main', __name__)

@api.route('/')
def home():
    return render_template('index.html')

# @api.route('/nmap', methods=['POST'])
# def nmap_query():
    # data = request.get_json()
    # ip_range = data.get('ip_range')
    # stdout = caller.run_nmap(ip_range)
    # data = parser.parse_nmap_xml(stdout)
    # return jsonify(statusCode= 200, data=data)


@api.route('/scan', methods=['GET', 'POST'])
def scan():
    results = []
    if request.method == 'POST':
        target = request.form.get('target')
        options = request.form.getlist('options')  # ej: ['-sS', '-O']

        xml_output = caller.run_nmap(target, options)
        results = parser.parse_nmap_xml(xml_output)  # deberías implementar este parser para devolver [{'ip':..., 'os':..., 'ports':[...]}, ...]

    return render_template('scanning.html', results=results)