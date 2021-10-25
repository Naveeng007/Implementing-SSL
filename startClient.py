from client.main import Client
from utils.convertors import text_to_bytes


if __name__ == '__main__':
    # Creating the Client instance
    client = Client('client.pem', 'project-client', 'world')

    # Connecting to the Server
    error = client.connect('localhost', 8310)

    if not error:
        payload = 'Hello World'
        payload = text_to_bytes(payload)

        client.send_payload(payload)
        client.disconnect()
