import socket
import M2Crypto
import random as rn
from OpenSSL import crypto
import Crypto.PublicKey.RSA
from utils.crypto import *
from utils.convertors import binary_to_int, bytes_to_text, int_to_binary, req_bytes, text_to_bytes
from utils.protocol import Error_Codes, load_certificate, Client_Status
from utils import rsa, sha1
import threading


class Client():

    def __init__(self, certificate_file, username, password):

        self.cert = 0  # Client certificate
        self.username = username  # Client's username
        self.password = password  # Client's password

        self.connection = None  # Connection to the server
        self.conn_status = 0  # Connection status
        self.buffer = bytearray()  # Receive Buffer
        self.is_connected = False  # True if there is currently a connection setup to the server

        self.session_id = None  # Received session ID
        self.certificate_reqired = 0  # True if server requires certificate

        self.client_random = None  # Client random
        self.server_random = None  # Server Random
        self.server_pubkey = 0  # Sever's PublicKey

        # Reading the Certificate
        self.cert = load_certificate('client/' + certificate_file)

    # Implements SSL Handshake to Setup connection with Server

    def connect(self, host, port):
        self.connection = socket.socket()
        self.connection.connect((host, port))
        self.set_conn_status(Client_Status.SOCKET_CREATED)

        # Sending Hello Message to Server
        self.connection.send(self.create_hello())
        self.set_conn_status(Client_Status.HELLO_SENT)

        # Receiving Hello Message from Server
        server_hello = self.receive_message()
        if server_hello is None:
            return

        # Processing the Hello Message from Server
        self.set_conn_status(Client_Status.HELLO_RECEIVED)
        error = self.process_hello(server_hello)
        if error:
            self.send_error(error)
            return

        # Sending Encrypted Session Key
        self.connection.send(self.create_key())
        self.set_conn_status(Client_Status.KEY_SENT)

        # Receiving Acknowledgement from Server
        setup_ack = self.receive_message()
        if setup_ack is None:
            return

        # Processing the Acknowledgement from Server
        self.set_conn_status(Client_Status.ACK_RECEIVED)
        error = self.process_ack(setup_ack)
        if error:
            self.send_error(error)
            return

        # Connection Setup
        self.set_conn_status(Client_Status.SETUP)
        self.is_connected = True

        # Starting the Payload listener
        listen_thread = threading.Thread(
            target=self.payload_listener, args=(self.connection,))
        listen_thread.start()

    # Receive incoming message and Add to Buffer
    def receive_message(self):

        while True:

            self.connection.settimeout(5)
            data = self.connection.recv(4096)
            if not data:
                break

            # Adding to the Input Buffer
            self.buffer.extend(data)

            # Length not Received yet
            if len(self.buffer) < 5:
                continue

            # Complete packet not received yet
            data_length = binary_to_int(self.buffer[1:5])
            if len(self.buffer) < data_length + 5:
                continue

            # Extracting Packet from Buffer
            packet = self.buffer[:data_length + 5]
            self.buffer = self.buffer[data_length + 5:]

            if packet[0] == ord('\x06'):
                print("ERROR RECEIVED...", packet[7])
                self.connection.close()
                return None

            return packet

    # Send an Error Message to Server and Close the connection
    def send_error(self, error_code):
        error_message = bytearray(10)

        # Adding Header
        error_message[0] = ord('\x06')
        error_message[1:5] = int_to_binary(5, 4)

        # Adding Session ID
        if self.session_id:
            error_message[5:7] = self.session_id
        else:
            error_message[5:7] = '\x00\x00'

        # Adding Error Code
        error_message[7] = int_to_binary(error_code, 1)

        # Adding Footer
        error_message[8] = ord('\xF0')
        error_message[9] = ord('\xF0')

        print(f"Sending Error Message with Code {error_code} to Server")

        self.connection.send(error_message)
        self.connection.close()
        return

    # Process Server Hello Message
    def process_hello(self, message):

        # Message Validations
        if len(message) != 1249:
            return Error_Codes.LENGTH_ERROR
        elif not message[0] == ord('\x02'):
            return Error_Codes.UNEXPECTED_MESSAGE_TYPE
        elif not message[5] == ord('\x64'):
            return Error_Codes.UNSUPPORTED_FIELD
        elif not message[6] == ord('\x65'):
            return Error_Codes.UNSUPPORTED_FIELD
        elif not message[1247] == ord('\xF0'):
            return Error_Codes.UNSUPPORTED_STRUCTURE
        elif not message[1248] == ord('\xF0'):
            return Error_Codes.UNSUPPORTED_STRUCTURE

        # Extracting Session details from Message
        self.server_random = bytes_to_text(message[7:39])
        self.session_id = message[39:41]
        self.certificate_reqired = (message[43] == ord('\x01'))

        # Extracting and Validating the Server certificate
        server_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, bytes_to_text(message[44:1247]))
        if server_cert.get_issuer().commonName != 'orion' or server_cert.has_expired():
            return Error_Codes.INCORRECT_SERVER_CERTIFICATE

        # Extracting the Server's PublicKey
        self.server_pubkey = Crypto.PublicKey.RSA.importKey(
            M2Crypto.X509.load_cert_string(message[44:1247]).get_pubkey().as_der())

        return None

    # Process Acknowledgement
    def process_ack(self, message):

        # Message Validations
        try:
            decrypt_data = decrypt_message(message[5:], self.master_secret)
        except:
            return Error_Codes.BAD_ENCRYPTION

        message = message[0:5] + decrypt_data
        if len(message) < 10:
            return Error_Codes.LENGTH_ERROR
        elif not message[0] == ord('\x05'):
            return Error_Codes.UNEXPECTED_MESSAGE_TYPE
        elif not message[5:7] == self.session_id:
            return Error_Codes.BAD_SESSION_ID
        elif not message[8] == ord('\xF0'):
            return Error_Codes.UNSUPPORTED_STRUCTURE
        elif not message[9] == ord('\xF0'):
            return Error_Codes.UNSUPPORTED_STRUCTURE

        return None

    # Create Client Hello Message to initiate connection with Server
    def create_hello(self):
        client_hello = bytearray(43)

        # Adding Header
        client_hello[0] = ord('\x01')
        client_hello[1:5] = int_to_binary(38, 4)
        client_hello[5] = ord('\x64')
        client_hello[6] = ord('\x65')

        # Generating Random Bytes
        client_random = ''
        for _ in range(7, 39):
            client_random += chr(rn.randint(0, 255))
        client_hello[7:39] = text_to_bytes(client_random)

        # Adding Footer
        client_hello[39] = ord('\x00')
        client_hello[40] = ord('\x2F')
        client_hello[41] = ord('\xF0')
        client_hello[42] = ord('\xF0')

        return client_hello

    # Create a Session Key packet
    def create_key(self):

        # Generating Pre-Master
        pre_master = ''
        for _ in range(48):
            pre_master += chr(rn.randint(0, 127))

        # Encrypting the Pre-Master
        pre_master_encrypt = rsa.encrypt(rsa.text_to_decimal(
            pre_master), self.server_pubkey.e, self.server_pubkey.n)
        key_length = req_bytes(pre_master_encrypt)

        client_key_message = bytearray(1234 + key_length)

        # Adding Header
        client_key_message[0] = ord('\x03')
        client_key_message[1:5] = int_to_binary(1229 + key_length, 4)

        # Adding Session Details
        client_key_message[5:7] = self.session_id
        client_key_message[7:1210] = self.cert
        client_key_message[1210:1212] = int_to_binary(key_length, 2)
        client_key_message[1212:1212 +
                           key_length] = int_to_binary(pre_master_encrypt, key_length)

        # Adding User Credentials
        user_credentials = sha1.sha1(self.userID + self.password)
        user_credentials2 = sha1.sha1(digestToString(
            user_credentials) + self.server_random)
        client_key_message[1212 + key_length:1232 +
                           key_length] = int_to_binary(user_credentials2, 20)

        # Adding Footer
        client_key_message[-1] = ord('\xF0')
        client_key_message[-2] = ord('\xF0')

        # Calculating and Storing the master_secret
        self.master_secret = sha1.sha1(
            digestToString(sha1.sha1(pre_master + digestToString(
                sha1.sha1('A' + pre_master + self.client_random + self.server_random)))) +
            digestToString(sha1.sha1(pre_master + digestToString(
                sha1.sha1('BB' + pre_master + self.client_random + self.server_random)))) +
            digestToString(sha1.sha1(pre_master + digestToString(
                sha1.sha1('CCC' + pre_master + self.client_random + self.server_random)))))

        return client_key_message

    # Close the existing connection
    def disconnect(self):
        if self.connection is not None:
            self.is_connected = False
            self.connection.close()

    # Set and Print the current Connection Status
    def set_conn_status(self, status):
        self.conn_status = status
        print(self.conn_status)

    # Start listening for, processing and replying to payload messages
    def payload_listener(self, conn):

        while True:
            if not self.is_connected:
                return

            payload = self.receive_message()
            if payload is None:
                return

            # Processing Payload
            error = self.process_payload(payload)
            if error:
                self.send_error(error)
                return

    # Process incoming payload
    def process_payload(self, message):

        # Message Validations
        try:
            decrypt_data = decrypt_message(message[5:], self.master_secret)
        except:
            return Error_Codes.BAD_ENCRYPTION

        message = message[0:5] + decrypt_data
        if len(message) < 12:
            return Error_Codes.LENGTH_ERROR
        elif not message[0] == ord('\x07'):
            return Error_Codes.UNEXPECTED_MESSAGE_TYPE
        elif not message[5:7] == self.session_id:
            return Error_Codes.BAD_SESSION_ID
        elif not message[-1] == ord('\xF0'):
            return Error_Codes.UNSUPPORTED_STRUCTURE
        elif not message[-2] == ord('\xF0'):
            return Error_Codes.UNSUPPORTED_STRUCTURE

        # Extracting payload length
        length = binary_to_int(message[7:11])
        if len(message) < 12 + length:
            return Error_Codes.LENGTH_ERROR

        # Extracting the payload
        payload = message[11:11 + length]
        print('Payload Received: ', bytes_to_text(payload))

        return None

    # Send a payload to the server
    def send_payload(self, payload):
        length = len(payload)
        if length > 4294967200:
            return

        # First 5 bytes not encrypted
        client_message = bytearray(5)
        client_message[0] = ord('\x07')

        # Creating the Payload
        client_message_to_encrypt = bytearray(8 + length)
        client_message_to_encrypt[0:2] = self.session_id
        client_message_to_encrypt[2:6] = int_to_binary(length, 4)
        client_message_to_encrypt[6:6 + length] = payload
        client_message_to_encrypt[-1] = ord('\xF0')
        client_message_to_encrypt[-2] = ord('\xF0')

        # Encrypting the Message
        client_message_encrypted = encrypt_message(
            client_message_to_encrypt, self.master_secret)

        # Combining the two parts
        client_message[1:5] = int_to_binary(len(client_message_encrypted), 4)
        self.connection.send(client_message + client_message_encrypted)
