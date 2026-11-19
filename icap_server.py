import argparse
import logging
import os
import socket

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

KEY_ENV = "ICAP_AES_KEY_HEX"
MAGIC = b"ENC1"
NONCE_SIZE = 12
TAG_SIZE = 16
ISTAG = '"sandbox-decrypt-v1"'
SERVICE_PATH = "/decrypt"
SOCKET_TIMEOUT = 30


def load_key():
    """Загрузка ключа из .env"""
    value = os.getenv(KEY_ENV, "").strip()
    if not value:
        raise RuntimeError(
            f"{KEY_ENV} не задан: скопируйте .env.example в .env "
            f"или передайте -e {KEY_ENV}=<64 hex-символа>"
        )
    try:
        key = bytes.fromhex(value)
    except ValueError:
        raise RuntimeError(f"{KEY_ENV} должен быть hex-строкой")
    if len(key) != 32:
        raise RuntimeError(f"{KEY_ENV} должен содержать 32 байта (64 hex-символа)")
    return key


KEY = load_key()


class IcapError(Exception):
    """Класс для обработки ошибок ICAP."""

    def __init__(self, code, reason):
        super().__init__(f"{code} {reason}")
        self.code = code
        self.reason = reason


def read_line(f):
    """Чтение строки из буфера, проверка на обрыв соединения."""
    line = f.readline()
    if not line.endswith(b"\n"):
        raise IcapError(400, "Bad Request")
    return line.rstrip(b"\r\n")


def read_headers(f):
    headers = {}
    while True:
        line = read_line(f)
        if not line:
            return headers
        # latin-1 не падает ни на каких байтах
        name, sep, value = line.decode("latin-1").partition(":")
        if not sep:
            raise IcapError(400, "Bad Request")
        headers[name.strip().lower()] = value.strip()


def parse_encapsulated(value):
    """'res-hdr=0, res-body=79' -> {'res-hdr': 0, 'res-body': 79}"""
    offsets = {}
    for part in value.split(","):
        name, sep, number = part.strip().partition("=")
        if not sep or not number.strip().isdigit():
            raise IcapError(400, "Bad Request")
        offsets[name.strip().lower()] = int(number)
    return offsets


def read_chunked_body(f):
    body = bytearray()
    while True:
        try:
            size = int(read_line(f), 16)  # размер chunk
        except ValueError:
            raise IcapError(400, "Bad Request")
        if size < 0:
            raise IcapError(400, "Bad Request")
        if size == 0:
            while read_line(f):
                pass
            return bytes(body)
        chunk = f.read(size)
        if len(chunk) != size or f.read(2) != b"\r\n":
            raise IcapError(400, "Bad Request")
        body += chunk


def get_service_path(url):
    """icap://127.0.0.1:1344/decrypt -> /decrypt"""
    if not url.startswith("icap://"):
        raise IcapError(400, "Bad Request")
    rest = url[len("icap://"):]
    slash = rest.find("/")
    return rest[slash:] if slash != -1 else "/"


def read_request(f):
    """Разобрать ICAP-запрос и вернуть (HTTP head, HTTP body)."""
    parts = read_line(f).decode("latin-1").split()
    if len(parts) != 3:
        raise IcapError(400, "Bad Request")
    method, url, version = parts
    if version != "ICAP/1.0":
        raise IcapError(505, "ICAP version not supported")
    if method != "RESPMOD":
        raise IcapError(405, "Method not allowed for service")
    if get_service_path(url) != SERVICE_PATH:
        raise IcapError(404, "ICAP Service not found")

    headers = read_headers(f)
    offsets = parse_encapsulated(headers.get("encapsulated", ""))
    if offsets.get("res-hdr") != 0 or "res-body" not in offsets:
        raise IcapError(400, "Bad Request")
    if "req-hdr" in offsets or "req-body" in offsets:
        raise IcapError(400, "Bad Request")

    # head читаем по offset
    head = f.read(offsets["res-body"])
    if len(head) != offsets["res-body"] or not head.endswith(b"\r\n\r\n"):
        raise IcapError(400, "Bad Request")
    if not head.startswith(b"HTTP/"):
        raise IcapError(400, "Bad Request")
    return head, read_chunked_body(f)


def decrypt_body(body):
    """ENC1: magic(4) + nonce(12) + ciphertext + tag(16)."""
    if len(body) < len(MAGIC) + NONCE_SIZE + TAG_SIZE:
        raise IcapError(400, "Bad Request")
    nonce = body[len(MAGIC):len(MAGIC) + NONCE_SIZE]
    ciphertext_and_tag = body[len(MAGIC) + NONCE_SIZE:]
    try:
        # пустой plaintext (контейнер ровно 32 байта) тоже валиден
        return AESGCM(KEY).decrypt(nonce, ciphertext_and_tag, None)
    except InvalidTag:
        raise IcapError(400, "Bad Request")


def replace_content_length(head, length):
    """Изменение Content-Length в HTTP-заголовке"""
    lines = head.split(b"\r\n")
    for i, line in enumerate(lines):
        name, sep, _ = line.partition(b":")
        if sep and name.lower() == b"content-length":
            lines[i] = name + b": " + str(length).encode("ascii")
            return b"\r\n".join(lines)
    raise IcapError(400, "Bad Request")


def build_response(head, body):
    icap_head = (
        "ICAP/1.0 200 OK\r\n"
        f"ISTag: {ISTAG}\r\n"
        f"Encapsulated: res-hdr=0, res-body={len(head)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    # тело отправляем одним chunk, повторять нарезку клиента не нужно
    chunks = b""
    if body:
        chunks = format(len(body), "x").encode("ascii") + b"\r\n" + body + b"\r\n"
    return icap_head + head + chunks + b"0\r\n\r\n"


def build_error(code, reason):
    # ISTag нужен и в ответах с ошибкой
    return (
        f"ICAP/1.0 {code} {reason}\r\n"
        f"ISTag: {ISTAG}\r\n"
        "Encapsulated: null-body=0\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")


def discard_rest(conn):
    """Дочитать остаток запроса, иначе close() отправит RST и ответ потеряется."""
    conn.settimeout(1)
    try:
        while conn.recv(65536):
            pass
    except OSError:
        pass


def handle_client(conn):
    conn.settimeout(SOCKET_TIMEOUT)
    f = conn.makefile("rb")  # буферизация: границы recv не важны
    try:
        try:
            head, body = read_request(f)
            if body.startswith(MAGIC):
                body = decrypt_body(body)
                head = replace_content_length(head, len(body))
            response = build_response(head, body)
            logging.info("200 OK, тело %d байт", len(body))
        except IcapError as error:
            logging.info("%d %s", error.code, error.reason)
            response = build_error(error.code, error.reason)
        conn.sendall(response)
        conn.shutdown(socket.SHUT_WR)  # клиент сразу видит конец ответа
        discard_rest(conn)
    except OSError as error:
        logging.info("ошибка соединения: %s", error)
    finally:
        f.close()
        conn.close()


def serve(sock):
    while True:
        try:
            conn, addr = sock.accept()
        except OSError:
            break  # слушающий сокет закрыт
        logging.info("соединение от %s", addr)
        try:
            handle_client(conn)
        except Exception:
            # ошибка одного клиента не должна останавливать сервер
            logging.exception("непредвиденная ошибка при обработке соединения")


def main():
    parser = argparse.ArgumentParser(description="ICAP RESPMOD сервер /decrypt")
    parser.add_argument("--host", default=os.getenv("ICAP_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("ICAP_PORT", "1344")))
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.host, args.port))
        sock.listen(5)
        logging.info("слушаю %s:%d", args.host, args.port)
        serve(sock)


if __name__ == "__main__":
    main()