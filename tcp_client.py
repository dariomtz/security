import socket
import nacl.secret
import nacl.utils
from nacl.bindings import sodium_increment
from nacl.signing import SigningKey

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
CHUNK_SIZE = 1024
VERIFY_KEY_BYTES_SIZE = 32


def main() -> None:
    key = nacl.utils.randombytes_deterministic(
        nacl.secret.SecretBox.KEY_SIZE,
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    )

    # Generate a new random signing key
    signing_key = SigningKey.generate()
    # Obtain the verify key for a given signing key
    verify_key = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    verify_key_bytes = verify_key.encode()

    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Send verify key bytes
        s.sendall(verify_key_bytes)

        # Send nonce once at the beginning
        s.sendall(nonce)
        with open("./data/client/file.txt", "rb") as file:
            while True:
                # Sends user and password
                user = input("User: ")
                password = input("Password: ")
                signed_cred = signing_key.sign(make_64_bytes(user + "=" + password))
                encrypted_cred = box.encrypt(signed_cred, nonce)
                s.sendall(encrypted_cred)
                nonce = sodium_increment(nonce)
                valid_credentials = int(str(s.recv(1)))
                if valid_credentials:
                    break

            while True:
                # read file in chunks instead of lines to be consistent with size of
                # encryption and decription
                chunk = file.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += bytes(" " * (16 - (len(chunk) % 16)), "utf-8")

                # sign data
                signed_data = signing_key.sign(chunk)
                # encrypt signed data
                encrypted_data = box.encrypt(signed_data, nonce).ciphertext
                # send encrypted signed data
                s.sendall(encrypted_data)
                # increment nonce to get a new one
                nonce = sodium_increment(nonce)


def make_64_bytes(string: str):
    by = bytes(string, "utf-8")
    by += b" " * (64 - len(by))
    return by


if __name__ == "__main__":
    main()
