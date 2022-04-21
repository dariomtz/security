import base64
import socket
import custom_random

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            file_data = b""
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                file_data += data

    with open("./data/server/received_file.txt", "wb") as file:
        file.write(file_data)


if __name__ == "__main__":
    main()
