import base64, json, os, sys
from os import environ as env
from service import service
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from flask import Flask, request, send_from_directory, jsonify, request
from flask_cors import CORS
from flask_api import status

sys.path.append("..")

app = Flask(__name__)
CORS(app, supports_credentials=True)

network_provider = os.getenv('NETWORK_PROVIDER')
ursula_uri = os.getenv('URSULA_URI')
ursula_uri2 = os.getenv('URSULA_URI_2')
ursula_uri3 = os.getenv('URSULA_URI_3')
ipfs_address = os.getenv('IPFS_ADDRESS')

nucypher = service.service(network_provider)
nucypher.connect(ursula_uri, ursula_uri2, ursula_uri3, ipfs_address)

@app.route('/user', methods=["POST"])
def create_user():
	nucypher.create_alice(request.json["username"], request.json["password"])
	return jsonify({'status': status.HTTP_201_CREATED})

@app.route('/data', methods=["POST"])
def add_data():
	policy_info, receipt = nucypher.add_data_and_grant_self_access(request.json["username"], request.json["password"], request.json["account"], request.json["filename"])
	
	return jsonify(policy_info=policy_info, receipt=receipt)

@app.route('/grant', methods=["POST"])
def grant_access():
	policy_info = nucypher.grant(request.json["username"], request.json["password"], request.json["account"], request.json["bob_username"], request.json["filename"])
	return jsonify(policy_info=policy_info)

if __name__ == '__main__':
	app.run(host="0.0.0.0")