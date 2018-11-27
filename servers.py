class StorageServer(object):
    """Simple implementation of a storage server using a key-value store.
    """
    def __init__(self):
        self.kv = {}

    def get(self, id):
        """Retrieves the value stored at `id`

        :param str id: The id to get
        :returns: The value, or None if `id` does not exist in the store
        :rtype: str or None
        """
        if id not in self.kv:
            return None
        return self.kv[id]

    def put(self, id, value):
        """Stores `value` at `id`

        :param str id: The id to store `value` at
        :param str value: The value to store

        :returns: True, if the `put` succeeded

        :raises TypeError: If id or value are not strings
        """
        if not isinstance(id, str):
            raise TypeError("id must be a string")
        if not isinstance(value, str):
            print(value)
            raise TypeError("value must be a string")
        self.kv[id] = value
        return True

    def delete(self, id):
        """Deletes the given `id` from the server.

        :param str id: The id to delete
        """
        if id in self.kv:
            del self.kv[id]


class PublicKeyServer(object):
    """Simple implementation of a public key server.
    """
    def __init__(self):
        self.sigkey = {}
        self.enckey = {}

    def put_signature_key(self, username, pubkey):
        """Set the public signature key for your `username`.

        :param str username: Your client's username
        :param pubkey: Your RSA public key
        :type pubkey: An RSA key object
        """
        self.sigkey[username] = pubkey

    def put_encryption_key(self, username, pubkey):
        """Set the public encryption key for your `username`.

        :param str username: Your client's username
        :param pubkey: Your ElGamal public key
        :type pubkey: An ElGamal key object
        """
        self.enckey[username] = pubkey


    def get_signature_key(self, username):
        """Get the public signature key associated with `username`.
        """
        if username in self.sigkey:
            return self.sigkey[username]
        return None


    def get_encryption_key(self, username):
        """Get the public encryption key associated with `username`.

        :param str username: The username to lookup the public key of.
        :returns: The ElGamal key object containing the public key, or `None` if
            the user does not have a key registered with the PublicKeyServer.
        """
        if username in self.enckey:
            return self.enckey[username]
        return None
