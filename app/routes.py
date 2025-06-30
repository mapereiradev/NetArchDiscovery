from flask import Blueprint, jsonify, render_template


api = Blueprint('api', __name__)

@api.route('/api/data')
def get_data():
    return jsonify({"message": "Hello from the API!", "items": [1,2,3]})


@api.route('/')
def home():
    return render_template('index.html')