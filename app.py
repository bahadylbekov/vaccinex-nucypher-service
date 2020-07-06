import base64, json, os, sys
from os import environ as env
from service import service
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from flask import Flask, request, send_from_directory, jsonify, request
from flask_cors import CORS
from flask_api import status
import io
from flask.helpers import send_file

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
	address = nucypher.create_alice(request.json["username"], request.json["password"])
	return jsonify(address=address)

@app.route('/encrypt', methods=["POST"])
def add_data():

	if len(request.files) > 0:
		data = request.files['file'].read()

	policy_info, receipt = nucypher.add_data_and_grant_self_access(request.form["username"], request.form["password"], request.form["account"], request.form["label"], data)
	
	return jsonify(policy_info=policy_info, receipt=receipt)

@app.route('/grant', methods=["POST"])
def grant_access():
	policy_info = nucypher.grant(request.json["username"], request.json["password"], request.json["account"], request.json["bob_username"], request.json["label"])
	return jsonify(policy_info=policy_info)

@app.route('/decrypt', methods=["POST"])
def download_and_decrypt_data():
	label = request.json["policy_info"]["label"]
	parsed_label = label.split(".")
	format = parsed_label[-1]
	print(format)
	decrypted_data = nucypher.downloadFile(request.json["username"], request.json["receipt"], request.json["policy_info"])
	if (decrypted_data is None):
		return jsonify({"Status": "Decription failed"})
	else:
		file = io.BytesIO()
		file.write(decrypted_data)
		file.seek(0)
		return send_file(file, attachment_filename=f"example."+format, as_attachment=True)


@app.route('/public_keys', methods=["POST"])
def get_public_keys():
	enc_pubkey, sig_pubkey = nucypher.reveal_public_keys(request.json["username"], True)
	return jsonify(enc_pubkey=enc_pubkey, sig_pubkey=sig_pubkey)

if __name__ == '__main__':
	app.run(host="0.0.0.0")