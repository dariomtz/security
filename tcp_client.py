import base64
import socket

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        with open("./data/client/file.txt", "rb") as file:
            for line in file.readlines():
                s.sendall(line)


if __name__ == "__main__":
    main()
