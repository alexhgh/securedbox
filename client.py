"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError

import json
import Crypto
from Crypto.PublicKey import RSA
from util import *
import binascii

def to_json_string(obj):
    """Convert basic Python objects into a JSON-serialized string.
    This can be useful for converting objects like lists or dictionaries into
    string format, instead of deriving your own data format.
    This function can correctly handle serializing RSA key objects.
    This uses the JSON library to dump the object to a string. For more
    information on JSON in Python, see the `JSON library
    <https://docs.python.org/3/library/json.html>`_ in the Python standard
    library.
    :param obj: A JSON-serializable Python object
    :returns: A JSON-serialized string for `obj`
    :raises TypeError: If `obj` isn't JSON serializable.
    """
    class CustomEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, Crypto.PublicKey.RSA._RSAobj):
                return {'__type__': '_RSAobj', 'PEMdata':
                        str(obj.exportKey(format='PEM'), 'utf-8')}
            if isinstance(obj, Crypto.PublicKey.ElGamal.ElGamalobj):
                return {'__type__': 'ElGamalobj', 'y': obj.y,
                        'g': obj.g, 'p': obj.p}
            return json.JSONEncoder.default(self, obj)
    return json.dumps(obj, cls=CustomEncoder)


def from_json_string(s):
    """Convert a JSON string back into a basic Python object.
    This function can correctly handle deserializing back into RSA key objects.
    This uses the JSON library to load the object from a string.
    For more information on JSON in Python, see the `JSON library
    <https://docs.python.org/3/library/json.html>`_ in the Python standard
    library.
    :param str s: A JSON string
    :returns: The Python object deserialized from `s`
    :raises JSONDecodeError: If `s` is not a valid JSON document.
    :raises TypeError: If `s` isn't a string.
    """
    def Custom_decoder(obj):
        if '__type__' in obj and obj['__type__'] == '_RSAobj':
            return RSA.importKey(obj['PEMdata'])
        if '__type__' in obj and obj['__type__'] == 'ElGamalobj':
            return ElGamal.construct(tuple(obj['p'], obj['g'], obj['y']))
        return obj
    return json.loads(s, object_hook=Custom_decoder)


def path_join(*strings):
    """Joins a list of strings putting a "/" between each.

    :param strings: a list of strings to join
    :returns: a string
    """
    return '/'.join(strings)

def compress(text):
    # print ("----------------------")
    # print ("before compression: " + text)
    # print("orginal size: " + str(len(text)))
    bin = ''
    for c in text:
        if (c == '0'):
            bin += '0000'
        elif (c == '1'):
            bin += '0001'
        elif (c == '2'):
            bin += '0010'
        elif (c == '3'):
            bin += '0011'
        elif (c == '4'):
            bin += '0100'
        elif (c == '5'):
            bin += '0101'
        elif (c == '6'):
            bin += '0110'
        elif (c == '7'):
            bin += '0111'
        elif (c == '8'):
            bin += '1000'
        elif (c == '9'):
            bin += '1001'
        elif (c == 'a'):
            bin += '1010'
        elif (c == 'b'):
            bin += '1011'
        elif (c == 'c'):
            bin += '1100'
        elif (c == 'd'):
            bin += '1101'
        elif (c == 'e'):
            bin += '1110'
        elif (c == 'f'):
            bin += '1111'
        else:
            print ('gg')

    sol = ''
    for i in range(0, len(bin), 8):
        bit = bin[i: i+8]
        ascii = chr(int(bit, 2))
        sol += ascii
    return sol

def decompress(text):
    recover = ''
    for ch in text:
        dec = ord(ch)
        bit = str(int(bin(dec)[2:])).zfill(8)
        recover += bit

    sol = ''
    for i in range(0, len(recover), 4):
        bit = recover[i:i+4]
        if (bit == '0000'):
            sol += '0'
        elif (bit == '0001'):
            sol += '1'
        elif (bit == '0010'):
            sol += '2'
        elif (bit == '0011'):
            sol += '3'
        elif (bit == '0100'):
            sol += '4'
        elif (bit == '0101'):
            sol += '5'
        elif (bit == '0110'):
            sol += '6'
        elif (bit == '0111'):
            sol += '7'
        elif (bit == '1000'):
            sol += '8'
        elif (bit == '1001'):
            sol += '9'
        elif (bit == '1010'):
            sol += 'a'
        elif (bit == '1011'):
            sol += 'b'
        elif (bit == '1100'):
            sol += 'c'
        elif (bit == '1101'):
            sol += 'd'
        elif (bit == '1110'):
            sol += 'e'
        elif (bit == '1111'):
            sol += 'f'
        else:
            print ("dec gg")
    # print("before DEmpression: " + sol)
    # print("receive size: " + str(len(text)))
    # print("------------------------")
    # print ()
    return sol


class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,username)

        self.public_key_enc = public_key_server.get_encryption_key(self.username)
        self.public_key_int = public_key_server.get_signature_key(self.username)

        key_enc = self.crypto.get_random_bytes(32)
        key_enc_key = self.crypto.get_random_bytes(32)
        key_int_key = self.crypto.get_random_bytes(32)

        share_key_enc = self.crypto.get_random_bytes(16)
        share_key_int = self.crypto.get_random_bytes(16)

        keys = key_enc + key_enc_key + key_int_key + share_key_enc + share_key_int

        cipher_key = self.crypto.asymmetric_encrypt(keys, self.public_key_enc)
        rsa_key = self.crypto.asymmetric_sign(cipher_key, self.rsa_priv_key)
        cipher_index = path_join(self.username, "key1")
        rsa_index = path_join(self.username, "key2")
        # print(rsa_key)
        # cipher_key = compress(cipher_key) # CHANGED 2
        rsa_key = compress(rsa_key)  # CHANGED 2

        if self.storage_server.get(cipher_index) is None:
            self.storage_server.put(cipher_index, cipher_key)
            self.storage_server.put(rsa_index, rsa_key)

        self.update_block = []
        self.update_tree = []

        self.pull_count = 0

    def symmetric_encryption(self, message, key, cipher_name=None,
                          mode_name='ECB', IV=None):
        digest = self.crypto.symmetric_encrypt(message, key, cipher_name=cipher_name, mode_name=mode_name, IV=IV)
        digest = compress(digest)
        return digest

    def symmetric_decryption(self, ciphertext, key, cipher_name=None,
                          mode_name='ECB', IV=None):
        ciphertext = decompress(ciphertext)
        plaintext = self.crypto.symmetric_decrypt(ciphertext, key, cipher_name=cipher_name, mode_name=mode_name, IV=IV)
        return plaintext

    def unique(self, tag):
        res = self.storage_server.get(tag)
        if res is None:
            return tag
        else:
            return None

    def get_symmetric_member_info(self, keys):
        enc_key = keys[:64]
        int_key = keys[64:128]
        IV = keys[128:160]

        return enc_key, int_key, IV

    def get_symmetric_info(self, keys):
        enc_key = keys[:64]
        int_key = keys[64:128]
        IV = keys[128:]

        return enc_key, int_key, IV

    def get_original_node_info(self, keys):
        file_id = keys[:12]
        node_enc = keys[12:76]
        node_int = keys[76:140]
        IV = keys[140:172]
        filename_enc = keys[172:332]

        return file_id, node_enc, node_int, IV, filename_enc

    def get_member_node_info(self, keys):
        file_id = keys[:16]
        private_aes = keys[16:80]
        private_mac = keys[80:144]
        IV = keys[144:176]
        filename_enc = keys[176:336]

        return file_id, private_aes, private_mac, IV, filename_enc

    def get_key(self, file_id):
        map1 = path_join(path_join(self.username, "map1"), file_id)
        map2 = path_join(path_join(self.username, "map2"), file_id)

        ciphertext_for_key = self.storage_server.get(map1)
        if (ciphertext_for_key is not None):
            ciphertext_for_key = decompress(ciphertext_for_key)
        mac_for_key = self.storage_server.get(map2)

        if (mac_for_key is not None):
            mac_for_key = decompress(mac_for_key)

        return ciphertext_for_key, mac_for_key

    def get_file_id(self, filename_enc):
        id_index1 = path_join(filename_enc, "id1")
        id_index2 = path_join(filename_enc, "id2")
        file_id = self.storage_server.get(id_index1)
        rsa_for_id = self.storage_server.get(id_index2)
        # if (file_id is not None): # changed
        #     file_id = decompress(file_id)
        # if (rsa_for_id is not None):
        #     rsa_for_id = decompress(rsa_for_id) # end of changed

        return file_id, rsa_for_id

    def put_key(self, file_id, ciphertext_for_key, mac_for_key):
        map1 = path_join(path_join(self.username, "map1"), file_id)
        map2 = path_join(path_join(self.username, "map2"), file_id)

        ciphertext_for_key = compress(ciphertext_for_key) # changed
        mac_for_key = compress(mac_for_key) # changed

        self.storage_server.put(map1, ciphertext_for_key)
        self.storage_server.put(map2, mac_for_key)

    def put_file_id(self, filename_enc, shared_id, rsa_for_id):
        # shared_id = compress(shared_id) # changed
        # rsa_for_id = compress(rsa_for_id) # changed

        self.storage_server.put(path_join(filename_enc, "id1"), shared_id)
        self.storage_server.put(path_join(filename_enc, "id2"), rsa_for_id)

    def retrieve_client_key(self, keys):
        k_plain = keys[0:64]
        k_enc_key = keys[64:128]
        k_int_key = keys[128:192]

        return k_plain, k_enc_key, k_int_key

    def retrieve_client_share_key(self, keys):
        share_key_enc = keys[192:224]
        share_key_int = keys[224:256]

        return share_key_enc, share_key_int

    def get_file_size(self, username, file_id):
        function = path_join(path_join(path_join(username, "d"), file_id), "filesize")
        server_file_size = self.storage_server.get(function)
        if (server_file_size is not None):
            server_file_size = decompress(server_file_size) #CHANGED

        return server_file_size

    def compare_node(self, username, curr, old, tree_map, file_id, private_mac):
        # compare hash
        if (curr["h"] != old["h"]):
            # add node to update tree list
            if (curr not in self.update_tree):
                self.update_tree.append(curr)

            if (curr["l"] == "" and curr["r"] == ""):
                # add block_id to update block list
                if (curr["b"] not in self.update_block):
                    self.update_block.append(curr["b"])
            else:
                curr_left = ""
                curr_right = ""

                # get curr tree's children
                for node in tree_map:
                    if (curr_left != "" and curr_right != ""):
                        break
                    if node["b"] == curr["l"]:
                        curr_left = node
                    if node["b"] == curr["r"]:
                        curr_right = node

                # get old tree's children
                function = path_join(path_join(path_join(path_join(username, "d"), file_id), "b"), str(old["l"]))
                left_str = self.storage_server.get(function)

                function = path_join(path_join(path_join(path_join(username, "d"), file_id), "b"), str(old["r"]))
                right_str = self.storage_server.get(function)

                if (left_str is None or right_str is None):
                    return False

                old_left = from_json_string(left_str)
                old_right = from_json_string(right_str)

                data = old_left["h"] + str(old_left["l"]) + str(old_left["r"]) + str(old_left["b"])
                recal_left_mac = self.crypto.message_authentication_code(data, private_mac, 'SHA256')
                data = old_right["h"] + str(old_right["l"]) + str(old_right["r"]) + str(old_right["b"])
                recal_right_mac = self.crypto.message_authentication_code(data, private_mac, 'SHA256')

                if (recal_left_mac != old_left["m"] or recal_right_mac != old_right["m"]):
                    return False

                # compare curr's and old's children
                r1 = self.compare_node(username, curr_left, old_left, tree_map, file_id, private_mac)
                r2 = self.compare_node(username, curr_right, old_right, tree_map, file_id, private_mac)
                return r1 and r2
        return True

    def efficient_update(self, file_id, username, plaintext, private_aes, private_mac, IV_for_data):
        # split plaintext into blocks
        text = plaintext[:]
        block_list = []
        while (len(text) >= 1024):
            block_list += [text[:1024]]
            text = text[1024:]
        block_list += [text]

        hash_list = []

        # computing hash of each data block
        for i in range(0, len(block_list)):
            ciphertext_for_data = self.crypto.symmetric_encrypt(block_list[i], private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data)
            hash_list.append(self.crypto.cryptographic_hash(ciphertext_for_data, 'SHA256'))

        # compute new merkle tree
        tree_list = []
        for i in range(len(hash_list)):
            tree_elem = {"h": "", "l": "", "r": "", "b": "", "m": ""}
            tree_elem["h"] = hash_list[i]
            tree_elem["b"] = i
            data = tree_elem["h"] + str(tree_elem["l"]) + str(tree_elem["r"]) + str(tree_elem["b"])
            tree_elem["m"] = self.crypto.message_authentication_code(data, private_mac, 'SHA256')
            tree_list.append(tree_elem)

        tree_map = tree_list[:]

        # building current merkle tree
        counter = len(hash_list)
        while (len(tree_list) != 1):
            new_tree_list = []
            for i in range(int(len(tree_list) / 2)):
                tree_elem = {"h": "", "l": "", "r": "", "b": "", "m": ""}
                tree_elem["l"] = tree_list[0]["b"]
                tree_elem["r"] = tree_list[1]["b"]
                tree_elem["h"] = self.crypto.cryptographic_hash(tree_list[0]["h"] + tree_list[1]["h"], 'SHA256')
                tree_elem["b"] = counter
                data = tree_elem["h"] + str(tree_elem["l"]) + str(tree_elem["r"]) + str(tree_elem["b"])
                tree_elem["m"] = self.crypto.message_authentication_code(data, private_mac, 'SHA256')
                counter += 1

                tree_list = tree_list[2:]
                new_tree_list.append(tree_elem)
                tree_map.append(tree_elem)

            tree_list = new_tree_list + tree_list

        curr_root = tree_map[len(tree_map) - 1]

        digest = self.get_file_size(username, file_id)
        old_file_size = -1

        # decrypt old file_size
        if (digest is not None):
            ciphertext_for_size = digest[:(len(digest) - 64)]
            mac_for_size = digest[(len(digest) - 64):]
            # Integrity check for data
            recal_size_mac = self.crypto.message_authentication_code(ciphertext_for_size + file_id, private_mac, 'SHA256')

            if recal_size_mac != mac_for_size:
                raise IntegrityError

            old_file_size = int(self.crypto.symmetric_decrypt(ciphertext_for_size, private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data))

        # if file_size doesn't change
        if (old_file_size == len(plaintext)):
            function = path_join(path_join(path_join(path_join(username, "d"), file_id), "b"), "-5")
            old_obj = self.storage_server.get(function)

            if (old_obj is None):
                return False

            old_root = from_json_string(old_obj)

            self.update_block = []
            result = self.compare_node(username, curr_root, old_root, tree_map, file_id, private_mac)
            if (result is False):
                return False

            # perform partial update on data blocks
            for i in self.update_block:
                ciphertext_for_data = self.crypto.symmetric_encrypt(block_list[i], private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data)
                mac_for_data = self.crypto.message_authentication_code(ciphertext_for_data + file_id, private_mac, 'SHA256')
                digest = ciphertext_for_data + mac_for_data
                digest = compress(digest) # CHANGED

                function = path_join(path_join(path_join(username, "d"), file_id), str(i))
                self.storage_server.put(function, digest)

            # perform partial update on merkle tree
            for i in self.update_tree:
                json_tree = to_json_string(i)
                function = path_join(path_join(path_join(path_join(username, "d"), file_id), "b"), str(i["b"]))
                # compress(json_tree)
                self.storage_server.put(function, json_tree)
            self.update_block = []

        # else update everything
        else:
            # update all data blocks
            for i in range(0, len(block_list)):
                ciphertext_for_data = self.crypto.symmetric_encrypt(block_list[i], private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data)
                mac_for_data = self.crypto.message_authentication_code(ciphertext_for_data + file_id, private_mac, 'SHA256')
                digest = ciphertext_for_data + mac_for_data
                digest = compress(digest) # CHANGED

                function = path_join(path_join(path_join(username, "d"), file_id), str(i))
                self.storage_server.put(function, digest)

            # update entire merkle tree
            for i in range(len(tree_map)):
                if (i == len(tree_map) - 1):
                    tree_map[i]["b"] = -5
                block_id = tree_map[i]["b"]
                json_tree = to_json_string(tree_map[i])
                function = path_join(path_join(path_join(path_join(username, "d"), file_id), "b"), str(block_id))
                self.storage_server.put(function, json_tree)

        cipher_file_size = self.crypto.symmetric_encrypt(str(len(plaintext)), private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data)
        mac_for_filesize = self.crypto.message_authentication_code(cipher_file_size + file_id, private_mac, 'SHA256')
        digest = cipher_file_size + mac_for_filesize
        digest = compress(digest) # CHANGED

        function = path_join(path_join(path_join(username, "d"), file_id), "filesize")
        self.storage_server.put(function, digest)

        ciphertext_for_data = self.crypto.symmetric_encrypt(str(len(block_list)), private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data)
        mac_for_data = self.crypto.message_authentication_code(ciphertext_for_data + file_id, private_mac, 'SHA256')
        digest = ciphertext_for_data + mac_for_data
        digest = compress(digest) # CHANGED

        function = path_join(path_join(path_join(username, "d"), file_id), "size")
        self.storage_server.put(function, digest)

        return True

    def upload(self, name, value):
        plaintext = value

        # filename Encrpytion start
        cipher_index = path_join(self.username, "key1")
        rsa_index = path_join(self.username, "key2")
        cipher_key = self.storage_server.get(cipher_index)
        if (cipher_key is None):
            return None
        rsa_key = self.storage_server.get(rsa_index)
        if (rsa_key is None):
            return None

        #cipher_key = decompress(cipher_key) # CHANGED 2
        rsa_key = decompress(rsa_key) # CHANGED 2
        status = self.crypto.asymmetric_verify(cipher_key, rsa_key, self.public_key_int)
        if (not status):
            raise IntegrityError

        keys = self.crypto.asymmetric_decrypt(cipher_key, self.elg_priv_key)
        k_plain, k_enc_key, k_int_key = self.retrieve_client_key(keys)

        user_and_filename = path_join(self.username, name)
        filename = self.crypto.cryptographic_hash(user_and_filename, 'SHA256')
        filename_enc = self.crypto.symmetric_encrypt(filename, k_plain, cipher_name='AES', mode_name='ECB')
        # filename Encrpytion end

        id_index1 = path_join(filename_enc, "id1")
        id_index2 = path_join(filename_enc, "id2")

        file_id = self.storage_server.get(id_index1)

        if (file_id != None):
            if (len(file_id) != 16): # Share: Member Node
                owner = self.username
                while (len(file_id) != 16):
                    shared_file_id_index = path_join(filename_enc, "shared_file_id")
                    shared_file_id = self.storage_server.get(shared_file_id_index)

                    head = path_join(owner, shared_file_id)
                    shared_keys_index = path_join(head, "shared_key")

                    shared_keys = self.storage_server.get(shared_keys_index)

                    shared_node_enc, shared_node_int, IV_for_data = self.get_symmetric_member_info(shared_keys)

                    cipher_data = self.storage_server.get(file_id)
                    MAC_shared_data, cipher_shared_data = cipher_data[:64], cipher_data[64:]

                    recal_shared_mac = self.crypto.message_authentication_code(cipher_shared_data, shared_node_int, 'SHA256')
                    if recal_shared_mac != MAC_shared_data:
                        raise IntegrityError
                    try:
                        shared_data = self.crypto.symmetric_decrypt(cipher_shared_data, shared_node_enc, cipher_name='AES', mode_name='CBC', IV=IV_for_data)
                    except:
                        raise IntegrityError

                    owner = shared_data.split("/")[0]
                    shared_data = shared_data.split("/", 1)[1]

                    if (len(shared_data) < 336): # Not original Node
                        file_id, shared_node_enc, shared_user_int, IV_for_data, filename_enc = self.get_original_node_info(shared_data)

                    else: # Located original Node, updating this Node
                        file_id, private_aes, private_mac, IV_for_data, filename_enc = self.get_member_node_info(shared_data)

                        # Efficient update
                        result = self.efficient_update(file_id, owner, plaintext, private_aes, private_mac, IV_for_data)
                        return result
            else: # Share Original Node
                ciphertext_for_key, mac_for_key = self.get_key(file_id)

                if (ciphertext_for_key is None):
                    return None
                if (mac_for_key is None):
                    return None
                # Integrity check for key

                IV_for_key = mac_for_key[0:32]
                mac_for_key = mac_for_key[32:]

                recal_key_mac = self.crypto.message_authentication_code(ciphertext_for_key, k_int_key, 'SHA256')
                if recal_key_mac != mac_for_key:
                    raise IntegrityError
                try:
                    plainkey = self.crypto.symmetric_decrypt(ciphertext_for_key, k_enc_key, cipher_name='AES', mode_name='CBC', IV=IV_for_key)
                except:
                    raise IntegrityError
                private_aes, private_mac, IV_for_data =  self.get_symmetric_info(plainkey)

        else: # Normal Node
            file_id = self.crypto.get_random_bytes(8)

            while (self.unique(file_id) == None):
                file_id = self.crypto.get_random_bytes(8)
            rsa_for_id = self.crypto.asymmetric_sign(file_id, self.rsa_priv_key)

            IV_for_data = self.crypto.get_random_bytes(16)
            IV_for_key = self.crypto.get_random_bytes(16)

            private_aes = self.crypto.get_random_bytes(32)
            private_mac = self.crypto.get_random_bytes(32)

            self.storage_server.put(id_index1, file_id)
            self.storage_server.put(id_index2, rsa_for_id)
            # file_id Encrpytion end

            # Key encrpytion start
            plainkey = private_aes + private_mac + IV_for_data
            ciphertext_for_key = self.crypto.symmetric_encrypt(plainkey, k_enc_key, cipher_name='AES', mode_name='CBC', IV=IV_for_key)
            mac_for_key = IV_for_key + self.crypto.message_authentication_code(ciphertext_for_key, k_int_key, 'SHA256')

            self.put_key(file_id, ciphertext_for_key, mac_for_key)
            # Key encryption End

        # Efficient update
        result = self.efficient_update(file_id, self.username, plaintext, private_aes, private_mac, IV_for_data)
        return result
        # Data Encryption end


    def download(self, name):
        # filename Encrpytion start
        cipher_index = path_join(self.username, "key1")
        rsa_index = path_join(self.username, "key2")
        cipher_key = self.storage_server.get(cipher_index)

        if (cipher_key is None):
          return None

        rsa_key = self.storage_server.get(rsa_index)
        if (rsa_key is None):
          return None

        #cipher_key = decompress(cipher_key) # CHANGED 2
        rsa_key = decompress(rsa_key) # CHANGED 2
        status = self.crypto.asymmetric_verify(cipher_key, rsa_key, self.public_key_int)
        if (not status):
            raise IntegrityError

        keys = self.crypto.asymmetric_decrypt(cipher_key, self.elg_priv_key)
        k_plain, k_enc_key, k_int_key = self.retrieve_client_key(keys)

        user_and_filename = path_join(self.username, name)
        filename = self.crypto.cryptographic_hash(user_and_filename, 'SHA256')
        filename_enc = self.crypto.symmetric_encrypt(filename, k_plain, cipher_name='AES', mode_name='ECB')
        # filename Encrpytion end

        # file_id Decrpytion start
        file_id, rsa_for_id = self.get_file_id(filename_enc)
        if (rsa_for_id is None):
          return None
        # check if the file exist on the server
        if file_id is None:
          return None

        # Integrity check for file_id
        status = self.crypto.asymmetric_verify(file_id, rsa_for_id, self.public_key_int)
        if (not status):
          raise IntegrityError
        # file_id Decrpytion end

        # check if this is a shared file
        if (len(file_id) == 16):
            ciphertext_for_key, mac_for_key = self.get_key(file_id)
            if (ciphertext_for_key is None):
              return None
            if (mac_for_key is None):
              return None
            # Integrity check for key

            IV_for_key, mac_for_key = mac_for_key[0:32], mac_for_key[32:]

            recal_key_mac = self.crypto.message_authentication_code(ciphertext_for_key, k_int_key, 'SHA256')
            if recal_key_mac != mac_for_key:
                raise IntegrityError
            try:
                plainkey = self.crypto.symmetric_decrypt(ciphertext_for_key, k_enc_key, cipher_name='AES', mode_name='CBC', IV=IV_for_key)
            except:
                raise IntegrityError
            private_aes, private_mac, IV_for_data = self.get_symmetric_info(plainkey)

            # Key Decryption end

            # Data Decryption start
            # Get size
            function = path_join(path_join(path_join(self.username, "d"), file_id), "size")
            digest = self.storage_server.get(function)
            digest = decompress(digest) # CHANGED
            if (digest is None):
              return None
            ciphertext_for_size = digest[:(len(digest) - 64)]
            mac_for_size = digest[(len(digest) - 64):]
            # Integrity check for data
            recal_size_mac = self.crypto.message_authentication_code(ciphertext_for_size + file_id, private_mac, 'SHA256')

            if recal_size_mac != mac_for_size:
                raise IntegrityError

            size = int(self.crypto.symmetric_decrypt(ciphertext_for_size, private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data))

            # Get data block
            plaintext = ""
            for i in range(0, size):
                function = path_join(path_join(path_join(self.username, "d"), file_id), str(i))
                digest = self.storage_server.get(function)
                digest = decompress(digest) # CHANGED
                if (digest is None):
                  return None

                ciphertext_for_data = digest[:(len(digest) - 64)]
                mac_for_data = digest[(len(digest) - 64):]

                # Integrity check for data
                recal_data_mac = self.crypto.message_authentication_code(ciphertext_for_data + file_id, private_mac, 'SHA256')

                if recal_data_mac != mac_for_data:
                    raise IntegrityError
                try:
                    plaintext += self.crypto.symmetric_decrypt(ciphertext_for_data, private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data)
                except:
                    raise IntegrityError
            # Data Decryption end

            return plaintext
        else:
            owner = self.username
            while (len(file_id) != 16):
                shared_file_id_index = path_join(filename_enc, "shared_file_id")
                shared_file_id = self.storage_server.get(shared_file_id_index)

                head = path_join(owner, shared_file_id)
                shared_keys_index = path_join(head, "shared_key")
                shared_keys = self.storage_server.get(shared_keys_index)

                shared_node_enc, shared_node_int, IV_for_data = self.get_symmetric_member_info(shared_keys)

                cipher_data = self.storage_server.get(file_id)

                MAC_shared_data = cipher_data[:64]
                cipher_shared_data = cipher_data[64:]

                recal_shared_mac = self.crypto.message_authentication_code(cipher_shared_data, shared_node_int, 'SHA256')
                if recal_shared_mac != MAC_shared_data:
                    raise IntegrityError
                try:
                    shared_data = self.crypto.symmetric_decrypt(cipher_shared_data, shared_node_enc, cipher_name='AES', mode_name='CBC', IV=IV_for_data)
                except:
                    raise IntegrityError

                owner = shared_data.split("/")[0]
                shared_data = shared_data.split("/", 1)[1]

                if (len(shared_data) < 336):
                    file_id, shared_node_enc, shared_node_int, IV_for_data, filename_enc = self.get_original_node_info(shared_data)
                else:
                    file_id, private_aes, private_mac, IV_for_data, filename_enc = self.get_member_node_info(shared_data)

            # Data Decryption start
            # Get size
            function = path_join(path_join(path_join(owner, "d"), file_id), "size")
            digest = self.storage_server.get(function)
            digest = decompress(digest) # CHANGED
            if (digest is None):
                return None
            ciphertext_for_size = digest[:(len(digest) - 64)]
            mac_for_size = digest[(len(digest) - 64):]
            # Integrity check for data
            recal_size_mac = self.crypto.message_authentication_code(ciphertext_for_size + file_id, private_mac, 'SHA256')

            if recal_size_mac != mac_for_size:
                raise IntegrityError
            try:
                size = int(self.crypto.symmetric_decrypt(ciphertext_for_size, private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data))
            except:
                raise IntegrityError
            # Get data block
            plaintext = ""
            for i in range(0, size):
                function = path_join(path_join(path_join(owner, "d"), file_id), str(i))
                digest = self.storage_server.get(function)
                digest = decompress(digest) # CHANGED
                if (digest is None):
                  return None

                ciphertext_for_data = digest[:(len(digest) - 64)]
                mac_for_data = digest[(len(digest) - 64):]

                # Integrity check for data
                recal_data_mac = self.crypto.message_authentication_code(ciphertext_for_data + file_id, private_mac, 'SHA256')

                if recal_data_mac != mac_for_data:
                    raise IntegrityError
                try:
                    plaintext += self.crypto.symmetric_decrypt(ciphertext_for_data, private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data)
                except:
                    raise IntegrityError
            # Data Decryption end

            return plaintext

    def share(self, user, name):
        cipher_index = path_join(self.username, "key1")
        rsa_index = path_join(self.username, "key2")
        cipher_key = self.storage_server.get(cipher_index)

        if (cipher_key is None):
            return None
        rsa_key = self.storage_server.get(rsa_index)
        if (rsa_key is None):
            return None

        #cipher_key = decompress(cipher_key) # CHANGED 2
        rsa_key = decompress(rsa_key) # CHANGED 2

        status = self.crypto.asymmetric_verify(cipher_key, rsa_key, self.public_key_int)
        if (not status):
            raise IntegrityError

        keys = self.crypto.asymmetric_decrypt(cipher_key, self.elg_priv_key)
        k_plain, k_enc_key, k_int_key = self.retrieve_client_key(keys)

        user_and_filename = path_join(self.username, name)
        filename = self.crypto.cryptographic_hash(user_and_filename, 'SHA256')
        filename_enc = self.crypto.symmetric_encrypt(filename, k_plain, cipher_name='AES', mode_name='ECB')

        # filename Encrpytion end

        # file_id Decrpytion start
        file_id, rsa_for_id = self.get_file_id(filename_enc)

        if (rsa_for_id is None):
            return None
        # check if the file exist on the server
        if file_id is None:
            return None

        # Integrity check for file_id
        status = self.crypto.asymmetric_verify(file_id, rsa_for_id, self.public_key_int)
        if (not status):
            raise IntegrityError
        # file_id Decrpytion end

        # determine if this is a shared node
        if (len(file_id) == 16):
            # Key Decrpytion start
            ciphertext_for_key, mac_for_key = self.get_key(file_id)
            if (ciphertext_for_key is None):
                return None
            if (mac_for_key is None):
                return None
            # Integrity check for key

            IV_for_key, mac_for_key = mac_for_key[0:32], mac_for_key[32:]

            recal_key_mac = self.crypto.message_authentication_code(ciphertext_for_key, k_int_key, 'SHA256')
            if recal_key_mac != mac_for_key:
                raise IntegrityError
            try:
                plainkey = self.crypto.symmetric_decrypt(ciphertext_for_key, k_enc_key, cipher_name='AES', mode_name='CBC', IV=IV_for_key)
            except:
                raise IntegrityError
            private_aes, private_mac, IV_for_data = self.get_symmetric_info(plainkey)
            # Key Decryption end
        else:
            shared_file_id_index = path_join(filename_enc, "shared_file_id")
            shared_file_id = self.storage_server.get(shared_file_id_index)

            head = path_join(self.username, shared_file_id)
            shared_keys_index = path_join(head, "shared_key")
            shared_keys = self.storage_server.get(shared_keys_index)

            private_aes, private_mac, IV_for_data = self.get_symmetric_member_info(shared_keys)

        shared_id = self.crypto.get_random_bytes(6)
        while self.storage_server.get(shared_id) is not None:
            shared_id = self.crypto.get_random_bytes(6)

        shared_data = self.username + "/" + file_id + private_aes + private_mac + IV_for_data + filename_enc

        shared_node_enc = self.crypto.get_random_bytes(32)
        shared_node_int = self.crypto.get_random_bytes(32)
        shared_data_IV = self.crypto.get_random_bytes(16)
        shared_file_id = self.crypto.get_random_bytes(16)

        shared_id_sign = self.crypto.asymmetric_sign(shared_id, self.rsa_priv_key)
        self_shared_id = shared_id + shared_id_sign

        head = path_join(filename_enc, user)
        shared_id_index = path_join(head, "sub_shared_id")
        self.storage_server.put(shared_id_index, self_shared_id)

        shared_file_id_sign = self.crypto.asymmetric_sign(shared_file_id, self.rsa_priv_key)
        self_shared_file_id = shared_file_id + shared_file_id_sign

        head = path_join(filename_enc, user)
        shared_file_id_index = path_join(head, "sub_shared_file_id")
        self.storage_server.put(shared_file_id_index, self_shared_file_id)

        cipher_shared_data = self.crypto.symmetric_encrypt(shared_data, shared_node_enc, cipher_name='AES', mode_name='CBC', IV=shared_data_IV)
        MAC_shared_data = self.crypto.message_authentication_code(cipher_shared_data, shared_node_int, 'SHA256')

        cipher_data = MAC_shared_data + cipher_shared_data

        self.storage_server.put(shared_id, cipher_data)

        # Add a new child list to the share node
        request = path_join(filename_enc, "childlist")
        share_key_enc, share_key_int = self.retrieve_client_share_key(keys)

        if (self.storage_server.get(request) is None or self.storage_server.get(request) == ""):
            # case 1: no user in the list
            new_list = user + "/"
            sign = self.crypto.asymmetric_sign(new_list, self.rsa_priv_key)
            upload_list = new_list + sign

            self.storage_server.put(request, upload_list)
        else:
            # case 2: there exist user in the list
            original_lst = self.storage_server.get(request)
            new_list = path_join(original_lst[:(len(original_lst) - 513)], user)
            new_list = new_list + "/"
            sign = self.crypto.asymmetric_sign(new_list, self.rsa_priv_key)
            upload_list = new_list + sign

            self.storage_server.put(request, upload_list)
        # End of adding new child list to the share node

        shared_user_enc = self.pks.get_encryption_key(user)

        send_data = shared_node_enc + shared_node_int + shared_data_IV + shared_id + shared_file_id
        send_data_enc = self.crypto.asymmetric_encrypt(send_data, shared_user_enc)
        send_data_rsa = self.crypto.asymmetric_sign(send_data_enc, self.rsa_priv_key)

        return send_data_rsa + send_data_enc



    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        recv_data_rsa = message[:512]
        recv_data_enc = message[512:]

        from_user_int = self.pks.get_signature_key(from_username)

        status = self.crypto.asymmetric_verify(recv_data_enc, recv_data_rsa, from_user_int)
        if (not status):
            raise IntegrityError

        recv_data = self.crypto.asymmetric_decrypt(recv_data_enc, self.elg_priv_key)

        # k1, k2, IV, shared_id
        shared_keys, shared_id, shared_file_id = recv_data[:160], recv_data[160:172], recv_data[172:]

        rsa_for_id = self.crypto.asymmetric_sign(shared_id, self.rsa_priv_key)

        cipher_index = path_join(self.username, "key1")
        rsa_index = path_join(self.username, "key2")
        cipher_key = self.storage_server.get(cipher_index)
        if (cipher_key is None):
            return None
        rsa_key = self.storage_server.get(rsa_index)
        if (rsa_key is None):
            return None

        # cipher_key = decompress(cipher_key) # CHANGED 2
        rsa_key = decompress(rsa_key) # CHANGED 2

        status = self.crypto.asymmetric_verify(cipher_key, rsa_key, self.public_key_int)
        if (not status):
            raise IntegrityError

        keys = self.crypto.asymmetric_decrypt(cipher_key, self.elg_priv_key)
        k_plain = keys[0:64]

        user_and_filename = path_join(self.username, newname)
        filename = self.crypto.cryptographic_hash(user_and_filename, 'SHA256')
        filename_enc = self.crypto.symmetric_encrypt(filename , k_plain, cipher_name='AES', mode_name='ECB')
        # filename Encrpytion end

        shared_file_id_index = path_join(filename_enc, "shared_file_id")
        self.storage_server.put(shared_file_id_index, shared_file_id)

        self.put_file_id(filename_enc, shared_id, rsa_for_id)

        head = path_join(self.username, shared_file_id)
        shared_keys_index = path_join(head, "shared_key")
        self.storage_server.put(shared_keys_index, shared_keys)

        return None


    def revoke(self, user, name):
        # filename Encrpytion start
        cipher_index = path_join(self.username, "key1")
        rsa_index = path_join(self.username, "key2")
        cipher_key = self.storage_server.get(cipher_index)
        if (cipher_key is None):
            return None
        rsa_key = self.storage_server.get(rsa_index)
        if (rsa_key is None):
            return None

        #cipher_key = decompress(cipher_key) # CHANGED 2
        rsa_key = decompress(rsa_key) # CHANGED 2

        status = self.crypto.asymmetric_verify(cipher_key, rsa_key, self.public_key_int)
        if (not status):
            raise IntegrityError

        keys = self.crypto.asymmetric_decrypt(cipher_key, self.elg_priv_key)
        k_plain = keys[0:64]
        k_enc_key = keys[64:128]
        k_int_key = keys[128:192]

        user_and_filename = path_join(self.username, name)
        filename = self.crypto.cryptographic_hash(user_and_filename, 'SHA256')
        filename_enc = self.crypto.symmetric_encrypt(filename, k_plain, cipher_name='AES', mode_name='ECB')
        # filename Encrpytion end

        file_id, rsa_for_id = self.get_file_id(filename_enc)
        # check if the file exist on the server
        if (rsa_for_id is None):
            return None
        if file_id is None:
            return None

        # Integrity check for file_id
        status = self.crypto.asymmetric_verify(file_id, rsa_for_id, self.public_key_int)
        if (not status):
            raise IntegrityError
        # file_id Decrpytion end

        # if file not exist, or current user is not file owner
        if (file_id is None or len(file_id) != 16):
            return None

        request = path_join(filename_enc, "childlist")
        childlist = self.storage_server.get(request)

        # file is never shared
        if (childlist is None or childlist == ""):
            return None

        children = childlist[:(len(childlist) - 512)]
        sign = childlist[(len(childlist) - 512):]

        # check integrity of the children list
        status = self.crypto.asymmetric_verify(children, sign, self.public_key_int)
        if (not status):
            raise IntegrityError

        # check if this is a shared file
        ciphertext_for_key, mac_for_key = self.get_key(file_id)
        if (ciphertext_for_key is None):
            return None
        if (mac_for_key is None):
            return None

        # re-encrypt data of the file
        IV_for_key, mac_for_key = mac_for_key[0:32], mac_for_key[32:]

        recal_key_mac = self.crypto.message_authentication_code(ciphertext_for_key, k_int_key, 'SHA256')
        if recal_key_mac != mac_for_key:
            raise IntegrityError

        try:
            plainkey = self.crypto.symmetric_decrypt(ciphertext_for_key, k_enc_key, cipher_name='AES', mode_name='CBC', IV=IV_for_key)
        except:
            raise IntegrityError
        private_aes, private_mac, IV_for_data = self.get_symmetric_info(plainkey)

        # Data Decryption start
        # Get size
        function = path_join(path_join(path_join(self.username, "d"), file_id), "size")
        digest = self.storage_server.get(function)
        digest = decompress(digest) # CHANGED
        if (digest is None):
            return None
        ciphertext_for_size = digest[:(len(digest) - 64)]
        mac_for_size = digest[(len(digest) - 64):]
        # Integrity check for data
        recal_size_mac = self.crypto.message_authentication_code(ciphertext_for_size + file_id, private_mac, 'SHA256')

        if recal_size_mac != mac_for_size:
            raise IntegrityError

        size = int(self.crypto.symmetric_decrypt(ciphertext_for_size, private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data))

        # Get data block
        plaintext = ""
        for i in range(0, size):
            function = path_join(path_join(path_join(self.username, "d"), file_id), str(i))
            digest = self.storage_server.get(function)
            digest = decompress(digest) # CHANGED
            if (digest is None):
                return None

            ciphertext_for_data = digest[:(len(digest) - 64)]
            mac_for_data = digest[(len(digest) - 64):]

            # Integrity check for data
            recal_data_mac = self.crypto.message_authentication_code(ciphertext_for_data + file_id, private_mac, 'SHA256')

            if recal_data_mac != mac_for_data:
                raise IntegrityError
            plaintext += self.crypto.symmetric_decrypt(ciphertext_for_data, private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data)
        # Data Decryption end

        file_id = self.crypto.get_random_bytes(8)
        while (self.unique(file_id) == None):
            file_id = self.crypto.get_random_bytes(8)
        rsa_for_id = self.crypto.asymmetric_sign(file_id, self.rsa_priv_key)

        IV_for_data = self.crypto.get_random_bytes(16)
        IV_for_key = self.crypto.get_random_bytes(16)

        private_aes = self.crypto.get_random_bytes(32)
        private_mac = self.crypto.get_random_bytes(32)

        self.put_file_id(filename_enc, file_id, rsa_for_id)

        plainkey = private_aes + private_mac + IV_for_data
        ciphertext_for_key = self.crypto.symmetric_encrypt(plainkey, k_enc_key, cipher_name='AES', mode_name='CBC', IV=IV_for_key)
        mac_for_key = IV_for_key + self.crypto.message_authentication_code(ciphertext_for_key, k_int_key, 'SHA256')

        self.put_key(file_id, ciphertext_for_key, mac_for_key)

        # Split data into blocks
        text = plaintext[:]
        block_list = []
        while (len(text) >= 1024):
            block_list += [text[:1024]]
            text = text[1024:]
        block_list += [text]

        # Data Encryption start
        for i in range(0, len(block_list)):
            ciphertext_for_data = self.crypto.symmetric_encrypt(block_list[i], private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data)
            mac_for_data = self.crypto.message_authentication_code(ciphertext_for_data + file_id, private_mac, 'SHA256')
            digest = ciphertext_for_data + mac_for_data
            digest = compress(digest) # CHANGED
            function = path_join(path_join(path_join(self.username, "d"), file_id), str(i))
            self.storage_server.put(function, digest)

        ciphertext_for_data = self.crypto.symmetric_encrypt(str(len(block_list)), private_aes, cipher_name='AES', mode_name='CBC', IV=IV_for_data)
        mac_for_data = self.crypto.message_authentication_code(ciphertext_for_data + file_id, private_mac, 'SHA256')
        digest = ciphertext_for_data + mac_for_data
        digest = compress(digest) # CHANGED
        function = path_join(path_join(path_join(self.username, "d"), file_id), "size")
        self.storage_server.put(function, digest)
        # Data Encryption end

        # update re-encrypt data for children
        for child in children[:-1].split("/"):
            if (child != user):
                # get shared_file_id for that child
                head = path_join(filename_enc, child)
                shared_file_id_index = path_join(head, "sub_shared_file_id")
                sub_shared_file_id = self.storage_server.get(shared_file_id_index)

                sub_shared_file_id, sub_shared_file_id_sign = sub_shared_file_id[:32], sub_shared_file_id[32:]
                status = self.crypto.asymmetric_verify(sub_shared_file_id, sub_shared_file_id_sign, self.public_key_int)
                if (not status):
                    raise IntegrityError

                # generate new shared_data
                shared_data = self.username + "/" + file_id + private_aes + private_mac + IV_for_data + filename_enc

                # generate new shared_keys
                shared_node_enc = self.crypto.get_random_bytes(32)
                shared_node_int = self.crypto.get_random_bytes(32)
                shared_data_IV = self.crypto.get_random_bytes(16)
                shared_keys = shared_node_enc + shared_node_int + shared_data_IV

                # encrypt data using new shared_keys
                cipher_shared_data = self.crypto.symmetric_encrypt(shared_data, shared_node_enc, cipher_name='AES', mode_name='CBC', IV=shared_data_IV)
                MAC_shared_data = self.crypto.message_authentication_code(cipher_shared_data, shared_node_int, 'SHA256')

                cipher_data = MAC_shared_data + cipher_shared_data

                # get shared_id for that child
                head = path_join(filename_enc, child)
                shared_id_index = path_join(head, "sub_shared_id")
                shared_id = self.storage_server.get(shared_id_index)

                shared_id, shared_id_sign = shared_id[:12], shared_id[12:]
                status = self.crypto.asymmetric_verify(shared_id, shared_id_sign, self.public_key_int)
                if (not status):
                    raise IntegrityError

                # update newly encrypted data in shared_id
                self.storage_server.put(shared_id, cipher_data)

                # update new keys in shared_key
                head = path_join(child, sub_shared_file_id)
                shared_keys_index = path_join(head, "shared_key")

                self.storage_server.put(shared_keys_index, shared_keys)

        # modify childlist, remove revoked child
        request = path_join(filename_enc, "childlist")
        new_list = ""
        for child in children[:-1].split("/"):
            if (new_list == ""):
                if (child != user):
                    new_list = child + "/"
            else:
                new_list = new_list + child + "/"

        if (new_list == ""):
            self.storage_server.put(request, "")
        else:
            sign = self.crypto.asymmetric_sign(new_list, self.rsa_priv_key)
            upload_list = new_list + sign
            self.storage_server.put(request, upload_list)

        return None
