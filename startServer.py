from server.main import Server


if __name__ == '__main__':
    # Creating the Server instance
    server = Server('server.pem', 'server_prv.key')

    # Connecting to the Server
    # server.add_account('project-client', 'Konklave123')
    # server.start()
