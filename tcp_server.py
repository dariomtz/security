from datetime import datetime
from fileinput import filename
import socket
import nacl.utils
import nacl.secret
from nacl.bindings import sodium_increment
from nacl.signing import VerifyKey


HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)
CHUNK_SIZE = 1024
VERIFY_KEY_BYTES_SIZE = 32
SIGN_SIZE = 64
CREDENTIALS_SIZE = 64


def main() -> None:
    key = nacl.utils.randombytes_deterministic(
        nacl.secret.SecretBox.KEY_SIZE,
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    )

    print("Crea un usuario")
    user = input("User: ")
    password = input("Password: ")

    box = nacl.secret.SecretBox(key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            # receive verified_key_bytes
            verified_key_bytes = conn.recv(VERIFY_KEY_BYTES_SIZE)
            # Create a VerifyKey object from a hex serialized public key
            verify_key = VerifyKey(verified_key_bytes)

            # receive nonce to decrypt
            nonce = conn.recv(nacl.secret.SecretBox.NONCE_SIZE)

            while True:
                # Receive credentials
                cred = conn.recv(CREDENTIALS_SIZE + box.MACBYTES + SIGN_SIZE)
                decrypted_cred = box.decrypt(cred, nonce)
                nonce = sodium_increment(nonce)
                verified_cred = verify_key.verify(decrypted_cred)
                user_try, password_try, rest = verified_cred.decode("utf-8").split("=")
                if user_try == user and password_try == password:
                    conn.sendall(b"1")
                    break
                else:
                    conn.sendall(b"0")

            filename = conn.recv(CREDENTIALS_SIZE + box.MACBYTES + SIGN_SIZE)
            decrypted_filename = box.decrypt(filename, nonce)
            verified_name = (
                verify_key.verify(decrypted_filename).decode("utf-8").split("/")[0]
            )
            nonce = sodium_increment(nonce)
            bitacora(user, verified_name)

            file_data = b""
            while True:
                # receive encrypted data
                # size of this is chunk + mac size
                data = conn.recv(CHUNK_SIZE + box.MACBYTES + SIGN_SIZE)
                if len(data) == 0:
                    break
                elif len(data) % 16 != 0:
                    data += bytes(" " * (16 - (len(data) % 16)), "utf-8")

                # decrypt using nonce
                decrypted_data = box.decrypt(data, nonce)
                verified_message = verify_key.verify(decrypted_data)
                file_data += verified_message
                # update nonce so that is same as in client
                nonce = sodium_increment(nonce)

    with open(f"./data/server/{verified_name}", "wb") as file:
        file.write(file_data)


def bitacora(string, filename):
    with open("./data/server/bitacora.txt", "a") as file:
        file.write(
            string
            + " respaldo el documento "
            + filename
            + " en "
            + str(datetime.now())
            + "\n"
        )


if __name__ == "__main__":
    main()
