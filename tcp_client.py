import socket
import nacl.secret
import nacl.utils
from nacl.bindings import sodium_increment

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
CHUNK_SIZE = 1024


def main() -> None:
    key = nacl.utils.randombytes_deterministic(
        nacl.secret.SecretBox.KEY_SIZE,
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    )

    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        # Send nonce once at the beginning
        s.sendall(nonce)
        with open("./data/client/file.txt", "rb") as file:
            while True:
                # read file in chunks instead of lines to be consistent with size of
                # encryption and decription
                chunk = file.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += bytes(" " * (16 - (len(chunk) % 16)), "utf-8")

                # encrypt nonce
                data = box.encrypt(chunk, nonce).ciphertext
                # send encrypted data
                s.sendall(data)
                # increment nonce to get a new one
                nonce = sodium_increment(nonce)


if __name__ == "__main__":
    main()
