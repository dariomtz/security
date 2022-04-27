import socket
import nacl.utils
import nacl.secret
from nacl.bindings import sodium_increment


HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)
CHUNK_SIZE = 1024


def main() -> None:
    key = nacl.utils.randombytes_deterministic(
        nacl.secret.SecretBox.KEY_SIZE,
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    )

    box = nacl.secret.SecretBox(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            # receive nonce to decrypt
            nonce = conn.recv(nacl.secret.SecretBox.NONCE_SIZE)

            file_data = b""
            while True:
                # receive encrypted data
                # size of this is chunk + mac size
                data = conn.recv(CHUNK_SIZE + box.MACBYTES)
                if len(data) == 0:
                    break
                elif len(data) % 16 != 0:
                    data += bytes(" " * (16 - (len(data) % 16)), "utf-8")

                # decrypt using nonce
                file_data += box.decrypt(data, nonce)
                # update nonce so that is same as in client
                nonce = sodium_increment(nonce)

    with open("./data/server/received_file.txt", "wb") as file:
        file.write(file_data)


if __name__ == "__main__":
    main()
