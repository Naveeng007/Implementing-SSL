from client.main import Client


if __name__ == '__main__':
    # Creating the Client instance
    client = Client('client.pem', 'hello', 'world')

    # Connecting to the Server
    # client.connect('localhost', 8310)

    client.create_hello()
