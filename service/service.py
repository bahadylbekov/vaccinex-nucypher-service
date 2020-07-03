import copy, os, logging, datetime, json, base58, base64, time
import maya
import msgpack
import ipfshttpclient
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
from nucypher.characters.lawful import Alice, Bob, Ursula, Enrico
from nucypher.config.characters import AliceConfiguration
from nucypher.config.keyring import NucypherKeyring
from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.crypto.kits import UmbralMessageKit
from nucypher.network.middleware import RestMiddleware
from nucypher.datastore.keypairs import DecryptingKeypair, SigningKeypair


class service(object):

    def __init__(self, network_provider):
        self.provider_uri = network_provider
        self.user_path = "users/"
        self.public_key_path = "/recipent.public.json"
        self.private_key_path = "/recipent.private.json"

    def connect(self, networkURL, second_provider, third_provider, ipfs_provider): 

        BlockchainInterfaceFactory.initialize_interface(provider_uri=self.provider_uri)
        self.ipfs_gateway_api = ipfshttpclient.connect(ipfs_provider)

        self.ursula = Ursula.from_seed_and_stake_info(
            seed_uri=networkURL,
            federated_only=True,
            minimum_stake=0
        )

        self.ursula2 = Ursula.from_teacher_uri(
            teacher_uri=networkURL,
            federated_only=True,
            min_stake=0
        )

        self.ursula3 = Ursula.from_teacher_uri(
            teacher_uri=networkURL,
            federated_only=True,
            min_stake=0
        )

        return True

    def generate_keys(self):
        enc_privkey = UmbralPrivateKey.gen_key()
        sig_privkey = UmbralPrivateKey.gen_key()

        recipient_privkeys = {
            'enc': enc_privkey.to_bytes().hex(),
            'sig': sig_privkey.to_bytes().hex(),
        }

        enc_pubkey = enc_privkey.get_pubkey()
        sig_pubkey = sig_privkey.get_pubkey()

        recipient_pubkeys = {
            'enc': enc_pubkey.to_bytes().hex(),
            'sig': sig_pubkey.to_bytes().hex()
        }

        return recipient_privkeys, recipient_pubkeys

    def configure_alice(self, path):
        return AliceConfiguration(
            config_root=os.path.join(path),
            known_nodes=[self.ursula, self.ursula2, self.ursula3], 
            start_learning_now=False,
            federated_only=True, 
            learn_on_same_thread=True,
            network_middleware=RestMiddleware(),
        )

    def create_alice(self, username, password):
        path = self.user_path + username        
        alice_config = self.configure_alice(path)
        alice_config.initialize(password=password)
        alice_config.keyring.unlock(password=password)
        self.Alice = alice_config.produce()
        alice_config_file = alice_config.to_configuration_file()
        self.Alice.start_learning_loop(now=True)

        private_keys, public_keys = self.generate_keys()

        with open(path + self.private_key_path, 'w') as file:
            json.dump(private_keys, file)

        with open(path + self.public_key_path, 'w') as f:
            json.dump(public_keys, f)

        return self.Alice
    
    def generate_policy(self, username, label):
        policy_end_datetime = maya.now() + datetime.timedelta(365)
        path = self.user_path + username
        self.configure_alice(path)
        
        policy_pubkey = self.Alice.get_policy_pubkey_from_label(label)

        return policy_pubkey

    def reveal_public_keys(self, username, serialized=False):

        public_keys = self.user_path + username + self.public_key_path
        
        with open(public_keys) as data_file:    
            data = json.load(data_file)
        
        enc_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(data["enc"]))
        sig_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(data["sig"]))

        if serialized:
            return (
                base58.b58encode(bytes.fromhex(data["enc"])).decode("utf-8"),
                base58.b58encode(bytes.fromhex(data["sig"])).decode("utf-8")
            )

        return (enc_pubkey, sig_pubkey)

    def calculate_powers(self, username):
        enc_pubkey, sig_pubkey = self.reveal_public_keys(username)

        powers_and_material = { DecryptingPower: enc_pubkey, SigningPower: sig_pubkey }

        return powers_and_material


    def reveal_private_keys(self, username):
        private_keys = self.user_path + username + self.private_key_path
        
        with open(private_keys) as data_file:    
            data = json.load(data_file)
        enc_privkey = UmbralPrivateKey.from_bytes(bytes.fromhex(data["enc"]))
        sig_privkey = UmbralPrivateKey.from_bytes(bytes.fromhex(data["sig"]))

        return enc_privkey, sig_privkey

    def uploadData(self, filename):

        policy_pubkey = self.Alice.get_policy_encrypting_key_from_label(filename.encode("utf-8"))

        data_source = Enrico(policy_encrypting_key=policy_pubkey)
        data_source_public_key = bytes(data_source.stamp)

        now = time.time()
        kits = list()
        file = open(filename, "r").read()
        now += 5
        data_representation = { 'data': file, 'timestamp': now, }
        plaintext = msgpack.dumps(data_representation, use_bin_type=True)

        message_kit, _signature = data_source.encrypt_message(plaintext)
        kit_bytes = message_kit.to_bytes()
        kits.append(kit_bytes)
        data = { 'data_source': data_source_public_key, 'kits': kits, }
        d = msgpack.dumps(data, use_bin_type=True)

        ipfs_hash = self.ipfs_gateway_api.add_bytes(d)

        receipt = {
            "data_source_public_key" : data_source_public_key.hex(),
            "hash_key" : ipfs_hash
        }
        return receipt


    def alice_from_configutation(self, username, password, account):
        path = self.user_path + username + '/'
        keyring_path = path + "keyring"
        full_path = path + 'alice.json'
        alice_config = self.configure_alice(path)
        
        configuration = alice_config.from_configuration_file(
            config_root=os.path.join(path),
            filepath=full_path,
            keyring=NucypherKeyring(
                account=account,
                keyring_root=os.path.join(keyring_path),
            ),
        )

        configuration.keyring.unlock(password)
        self.Alice = configuration.produce()
        return self.Alice


    def grant(self, username, password, account, bob_username, filename):
        self.Alice = self.alice_from_configutation(username, password, account)

        powers_and_material = self.calculate_powers(bob_username)
        bob = Bob.from_public_keys(powers_and_material=powers_and_material, federated_only=True)
        
        policy_end_datetime = maya.now() + datetime.timedelta(days=365)
        label = filename.encode("utf-8")

        self.Alice.start_learning_loop(now=True)
        policy = self.Alice.grant(bob, label, m=1, n=1, expiration=policy_end_datetime)
        alices_pubkey = bytes(self.Alice.stamp)

        policy_info = {
            "policy_pubkey" : policy.public_key.to_bytes().hex(),
            "alice_sig_pubkey" : base58.b58encode(alices_pubkey).decode("utf-8"),
            "label" : label.decode("utf-8")
        }

        return policy_info


    def add_data_and_grant_self_access(self, username, password, account, filename):
        policy_info = self.grant(username, password, account, username, filename)
        receipt = self.uploadData(filename)

        return policy_info, receipt
        
    
    def downloadFile(self, filename, username, receipt, policy_info):
        hash = receipt['hash_key']
        input = self.ipfs.cat(hash)

        enc_privkey, sig_privkey = self.reveal_private_keys(username)

        bob_enc_key = DecryptingKeypair(private_key=enc_privkey)
        bob_sig_keyp = SigningKeypair(private_key=sig_privkey)
        enc_power = DecryptingPower(keypair=bob_enc_key)
        sig_power = SigningPower(keypair=bob_sig_keyp)
        power_ups = [enc_power, sig_power]

        authorizedRecipient = Bob(
            federated_only=True,
            crypto_power_ups=power_ups,
            start_learning_now=True,
            abort_on_learning_error=True,
            known_nodes=[self.ursula, self.ursula2, self.ursula3], 
            save_metadata=False,
            network_middleware=RestMiddleware(),
        )

        policy_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(policy_info["policy_pubkey"]))

        enrico_as_understood = Enrico.from_public_keys(
            {SigningPower: UmbralPublicKey.from_bytes(bytes.fromhex(receipt['data_source_public_key']))},
            policy_encrypting_key=policy_pubkey
        )
        alice_pubkey_restored = UmbralPublicKey.from_bytes((policy_info['alice_sig_pubkey']))
        authorizedRecipient.join_policy(policy_info['label'].encode(), alice_pubkey_restored)
        
        kit = UmbralMessageKit.from_bytes(input)

        delivered_cleartexts = authorizedRecipient.retrieve(message_kit=kit,
                                        data_source=enrico_as_understood,
                                        alice_verifying_key=alice_pubkey_restored,
                                        label=(policy_info['label'].encode()))

        data = base64.b64decode(delivered_cleartexts[0])
        output = open('./'+ filename, 'wb')
        output.write(data)
        output.close()