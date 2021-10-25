import socket
import M2Crypto
import random as rn
from OpenSSL import crypto
import Crypto.PublicKey.RSA
from utils.crypto import *
from utils.convertors import binary_to_int, bytes_to_text, int_to_binary, text_to_bytes
from utils.protocol import Error_Codes, load_certificate, load_private_key
from utils import rsa, sha1
import threading


class Server():

    def __init__(self, certificate_file, private_key_file):

        self.cert = 0  # Server certificate
        self.usernames = dict()  # All received user IDs
        self.accounts = dict()  # All registered user accounts

        self.private_key = 0  # Server private key
        self.max_server_id = 0  # Next session ID to assign

        self.connections = list()  # All current connections
        self.statuses = dict()  # Status of each current connection
        self.buffers = dict()  # All current receive buffers
        self.is_connected = dict()  # Connections to various Clients

        self.client_randoms = dict()  # All received client randoms
        self.server_randoms = dict()  # All generated server randoms
        self.client_pubkeys = dict()  # All received client pubkeys
        self.master_secrets = dict()  # All generated master secrets
        self.session_ids = dict()  # All generated session IDs

        # Reading the Certificate
        self.cert = load_certificate('server/' + certificate_file)

        # Reading the Private Key
        self.private_key = load_private_key('server/' + private_key_file)

    # Register an account
    def add_account(self, username, password):
        self.accounts[username] = sha1.sha1(username + password)

    # Start the server
    def start(self):
        print("Starting the Server...")

        server_socket = socket.socket()
        server_socket.bind(('0.0.0.0', 8310))
        server_socket.listen(1024)

        # Start thread dedicated to listening for new connections
        listen_thread = threading.Thread(
            target=self.listen, args=(server_socket,))
        listen_thread.start()

    # Listen for new incoming connections
    def listen(self, server_socket):
        print("Server Listening to New Connections...")

        while True:
            print('Listening for new connection...')
            conn, _ = server_socket.accept()
            self.connections.append(conn)
            self.statuses[conn] = 1

            # Starting new thread for every new connection
            process_thread = threading.Thread(
                target=self.connect, args=(conn,))
            process_thread.start()

    # Process incoming packets for SSL Handshake
    def connect(self, conn):

        # Start with empty buffer
        self.buffers[conn] = bytearray()

        skip_recv = False
        while True:
            if not skip_recv:
                data = conn.recv(4096)
                if not data:
                    break
                self.buffers[conn].extend(data)

            if len(self.buffers[conn]) < 5:
                skip_recv = False
                continue

            next_length = binary_to_int(self.buffers[conn][1:5])
            if len(self.buffers[conn]) < next_length + 5:
                skip_recv = False
                continue

            packet = self.buffers[conn][:next_length + 5]
            if packet[0] == ord('\x06'):
                print("ERROR RECEIVED...", packet[7])
                conn.close()
                return

            elif self.statuses[conn] == 1:
                error = self.process_hello(packet, conn)
                if error:
                    self.send_error(conn, error)
                    return
                else:
                    conn.send(self.create_hello(conn))
                    self.statuses[conn] = 3

            elif self.statuses[conn] == 3:
                error = self.process_key(packet, conn)
                if error:
                    self.send_error(conn, error)
                    return
                else:
                    conn.send(self.create_ack(conn))
                    self.statuses[conn] = -1

                    self.buffers[conn] = self.buffers[conn][next_length + 5:]
                    self.process_payloads(conn)
                    return

            skip_recv = True
            self.buffers[conn] = self.buffers[conn][next_length + 5:]

    # Process Client Hello Message
    def process_hello(self, message, conn):
        print("Processing Client Hello Received from", conn)

        # Message Validations
        if len(message) != 43:
            return Error_Codes.LENGTH_ERROR
        elif not message[0] == ord('\x01'):
            return Error_Codes.UNEXPECTED_MESSAGE_TYPE
        elif not message[5] == ord('\x64'):
            return Error_Codes.UNSUPPORTED_FIELD
        elif not message[6] == ord('\x65'):
            return Error_Codes.UNSUPPORTED_FIELD
        elif not message[-1] == ord('\xF0'):
            return Error_Codes.UNSUPPORTED_STRUCTURE
        elif not message[-2] == ord('\xF0'):
            return Error_Codes.UNSUPPORTED_STRUCTURE

        # Extracting client_random
        self.client_randoms[conn] = bytes_to_text(message[7:39])

        return None

    # Send an Error Message to Client and Close the connection
    def send_error(self, conn, error_code):
        print("Error Occurred with Code:", error_code)

        error_message = bytearray(10)

        # Adding Header
        error_message[0] = ord('\x06')
        error_message[1:5] = int_to_binary(5, 4)

        # Adding Session ID
        if self.session_ids.get(conn):
            error_message[5:7] = self.session_ids[conn]
        else:
            error_message[5] = ord('\x00')
            error_message[6] = ord('\x00')

        # Adding Error Code
        error_message[7:8] = int_to_binary(error_code, 1)

        # Adding Footer
        error_message[8] = ord('\xF0')
        error_message[9] = ord('\xF0')

        print(f"Sending Error Message with Code {error_code} to Server")

        conn.send(error_message)
        conn.close()
        return

    # Create Server Hello Message to continue connection with Client
    def create_hello(self, conn):
        print('Creating Hello Message for Client:', conn)

        server_hello = bytearray(1249)

        # Adding Header
        server_hello[0] = ord('\x02')
        server_hello[1:5] = int_to_binary(1244, 4)
        server_hello[5] = ord('\x64')
        server_hello[6] = ord('\x65')

        # Generating Random Bytes
        self.server_randoms[conn] = ''
        for _ in range(7, 39):
            self.server_randoms[conn] += chr(rn.randint(0, 255))
        server_hello[7:39] = text_to_bytes(self.server_randoms[conn])

        # Computing next session ID
        server_id = int_to_binary(self.max_server_id, 2)
        self.max_server_id += 1
        self.max_server_id %= 65535

        # Adding Session ID to message
        server_hello[39:41] = server_id
        self.session_ids[conn] = server_hello[39:41]

        # Adding Certificate and Footer
        server_hello[41] = ord('\x00')
        server_hello[42] = ord('\x2F')
        server_hello[43] = ord('\x01')

        server_hello[44:1247] = self.cert
        server_hello[1247] = ord('\xF0')
        server_hello[1248] = ord('\xF0')

        return server_hello

    # Process Client Key Message
    def process_key(self, message, conn):
        print("Processing Client key received from", conn)

        # Message Validations
        if len(message) < 1234:
            return Error_Codes.LENGTH_ERROR
        elif not message[0] == ord('\x03'):
            return Error_Codes.UNEXPECTED_MESSAGE_TYPE
        elif not message[5:7] == self.session_ids[conn]:
            return Error_Codes.BAD_SESSION_ID
        elif not message[-1] == ord('\xF0'):
            return Error_Codes.UNSUPPORTED_STRUCTURE
        elif not message[-2] == ord('\xF0'):
            return Error_Codes.UNSUPPORTED_STRUCTURE

        # Extracting and Validating the Server certificate
        client_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, bytes_to_text(message[7:1210]))
        if client_cert.get_issuer().commonName != 'orion':
            return Error_Codes.INCORRECT_CLIENT_CERTIFICATE

        # Extracting Client's PublicKey
        self.client_pubkeys[conn] = Crypto.PublicKey.RSA.importKey(
            M2Crypto.X509.load_cert_string(bytes_to_text(message[7:1210])).get_pubkey().as_der())

        # Extractint and Decrypting the pre_master
        length = binary_to_int(message[1210:1212])
        if len(message) != 1234 + length:
            return Error_Codes.LENGTH_ERROR

        pre_master = rsa.decimal_to_text(rsa.decrypt(binary_to_int(
            message[1212:1212 + length]), self.private_key.d, self.private_key.n), 48)

        # Validating user Credentials
        username = client_cert.get_subject().commonName
        if not self.accounts.get(username):
            return Error_Codes.INCORRECT_LOGIN

        expected_hash = sha1.sha1(digestToString(
            self.accounts[username]) + self.server_randoms[conn])
        if not message[1212 + length:1232 + length] == int_to_binary(expected_hash, 20):
            return Error_Codes.INCORRECT_LOGIN
        self.usernames[conn] = username

        # Calculating master secret
        server_random = self.server_randoms[conn]
        client_random = self.client_randoms[conn]

        master_secret = sha1.sha1(
            digestToString(sha1.sha1(
                pre_master + digestToString(sha1.sha1('A' + pre_master + client_random + server_random))))
            + digestToString(sha1.sha1(
                pre_master + digestToString(sha1.sha1('BB' + pre_master + client_random + server_random))))
            + digestToString(sha1.sha1(
                pre_master + digestToString(sha1.sha1('CCC' + pre_master + client_random + server_random)))))

        self.master_secrets[conn] = master_secret

        return None

    # Create a Server Acknowledgement
    def create_ack(self, conn):
        print("Creating a Connection Acknowledgement for Client:", conn)

        # First 5 bytes are not encrypted
        server_ack = bytearray(5)
        server_ack[0] = ord('\x05')

        # Preparing Message
        server_ack_to_encrypt = bytearray(5)
        server_ack_to_encrypt[0:2] = self.session_ids[conn]
        server_ack_to_encrypt[3] = ord('\xF0')
        server_ack_to_encrypt[4] = ord('\xF0')

        # Encrypting the Message
        server_ack_encrypted_part = encrypt_message(
            server_ack_to_encrypt, self.master_secrets[conn])

        # Combining the two parts
        server_ack[1:5] = int_to_binary(len(server_ack_encrypted_part), 4)

        return server_ack + server_ack_encrypted_part

    # Process incoming packets for secure connection
    def process_payloads(self, conn):
        print("Payload Listener for Client:", conn)

        skip_recv = False
        self.is_connected[conn] = True

        while True:
            if not self.is_connected[conn]:
                return

            if not skip_recv:
                data = conn.recv(4096)
                if not data:
                    break
                self.buffers[conn].extend(data)

            if len(self.buffers[conn]) < 5:
                skip_recv = False
                continue

            next_length = binary_to_int(self.buffers[conn][1:5])
            if len(self.buffers[conn]) < next_length + 5:
                skip_recv = False
                continue

            packet = self.buffers[conn][:next_length + 5]
            if packet[0] == ord('\x06'):
                print("ERROR RECEIVED...", packet[7])
                self.is_connected[conn] = False
                conn.close()
                return None

            error = self.process_payload(packet, conn)
            if error:
                self.send_error(conn, error)
                continue

            skip_recv = True
            self.buffers[conn] = self.buffers[conn][next_length + 5:]

    # Process a received payload packet
    def process_payload(self, message, conn):
        print("Processing Payload from Client:", conn)

        # Message Validations
        try:
            decrypt_data = decrypt_message(
                message[5:], self.master_secrets[conn])
        except:
            return Error_Codes.BAD_ENCRYPTION

        message = message[0:5] + decrypt_data

        print(message)

        if len(message) < 12:
            return Error_Codes.LENGTH_ERROR
        elif not message[0] == ord('\x07'):
            return Error_Codes.UNEXPECTED_MESSAGE_TYPE
        elif not message[5:7] == self.session_ids[conn]:
            return Error_Codes.BAD_SESSION_ID

        # Extracting payload length
        length = binary_to_int(message[7:11])
        if len(message) < 12 + length:
            return Error_Codes.LENGTH_ERROR

        # Extracting the payload
        payload = message[11:11 + length]
        print('Payload Received: ', bytes_to_text(payload))

        return None

    # Create a payload packet
    def create_payload(self, payload, conn):
        length = len(payload)
        if length > 4294967200:
            return

        # First 5 bytes not encrypted
        server_message = bytearray(5)
        server_message[0] = ord('\x07')

        # Creating the Payload
        server_message_to_encrypt = bytearray(8 + length)
        server_message_to_encrypt[0:2] = self.session_ids[conn]
        server_message_to_encrypt[2:6] = int_to_binary(length, 4)
        server_message_to_encrypt[6:6 + length] = payload
        server_message_to_encrypt[-1] = ord('\xF0')
        server_message_to_encrypt[-2] = ord('\xF0')

        # Encrypting the Message
        server_message_encrypted = encrypt_message(
            server_message_to_encrypt, self.master_secrets[conn])

        # Combining the two parts
        server_message[1:5] = int_to_binary(len(server_message_encrypted), 4)

        return server_message + server_message_encrypted
