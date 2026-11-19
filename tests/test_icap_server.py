import os
import random
import socket
import threading
import time

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import icap_server

KEY = bytes.fromhex(os.environ["ICAP_AES_KEY_HEX"])


@pytest.fixture(scope="session")
def server_port():
    """Фикстура для запуска сервера"""
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    port = sock.getsockname()[1]
    thread = threading.Thread(target=icap_server.serve, args=(sock,), daemon=True)
    thread.start()
    yield port
    try:
        sock.shutdown(socket.SHUT_RDWR)  # разбудить блокирующий accept()
    except OSError:
        pass
    sock.close()
    thread.join(timeout=5)


def encrypt_body(plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return b"ENC1" + nonce + AESGCM(KEY).encrypt(nonce, plaintext, None)


def make_head(body_size: int) -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(body_size).encode() + b"\r\n"
        b"\r\n"
    )


def random_chunks(total: int, rng: random.Random, max_size: int = 4096) -> list:
    sizes = []
    left = total
    while left > 0:
        size = rng.randint(1, min(max_size, left))
        sizes.append(size)
        left -= size
    return sizes


def build_request(head, body, chunk_sizes=None, path="/decrypt",
                  method="RESPMOD", version="ICAP/1.0", upper_hex=False):
    if chunk_sizes is None:
        chunk_sizes = [len(body)] if body else []
    assert sum(chunk_sizes) == len(body)
    payload = bytearray()
    pos = 0
    for size in chunk_sizes:
        size_line = format(size, "X" if upper_hex else "x").encode()
        payload += size_line + b"\r\n" + body[pos:pos + size] + b"\r\n"
        pos += size
    payload += b"0\r\n\r\n"
    request = (
        f"{method} icap://127.0.0.1:1344{path} {version}\r\n"
        "Host: 127.0.0.1:1344\r\n"
        "Connection: close\r\n"
        f"Encapsulated: res-hdr=0, res-body={len(head)}\r\n"
        "\r\n"
    ).encode("ascii")
    return request + head + bytes(payload)


def roundtrip(port, payload, piece_size=None):
    """Отправить запрос и читать ответ до EOF."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
        if piece_size is None:
            conn.sendall(payload)
        else:
            for i in range(0, len(payload), piece_size):
                conn.sendall(payload[i:i + piece_size])
                time.sleep(0.001)
        response = bytearray()
        while True:
            data = conn.recv(65536)
            if not data:
                break
            response += data
    return bytes(response)


def dechunk(data: bytes) -> bytes:
    """Декодировать chunked body и строго проверить его фрейминг."""
    body = bytearray()
    while True:
        line, sep, data = data.partition(b"\r\n")
        assert sep, "строка размера chunk не заканчивается CRLF"
        size = int(line, 16)
        if size == 0:
            assert data == b"\r\n", "некорректный терминальный chunk"
            return bytes(body)
        assert len(data) >= size + 2, "обрезанный chunk"
        assert data[size:size + 2] == b"\r\n", "нет CRLF после данных chunk"
        body += data[:size]
        data = data[size + 2:]


def parse_response(raw: bytes):
    """Вернуть (статус, ICAP-заголовки, HTTP head,тело) по offset'ам Encapsulated."""
    head_part, sep, rest = raw.partition(b"\r\n\r\n")
    assert sep, "нет пустой строки после ICAP-заголовков"
    lines = head_part.decode("latin-1").split("\r\n")
    assert lines[0].startswith("ICAP/1.0 "), lines[0]
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    assert headers.get("istag"), "ISTag обязателен в каждом ICAP-ответе"
    if status != 200:
        return status, headers, None, None
    offsets = {}
    for item in headers["encapsulated"].split(","):
        name, _, value = item.strip().partition("=")
        offsets[name] = int(value)
    assert offsets["res-hdr"] == 0
    http_head = rest[:offsets["res-body"]]
    assert http_head.endswith(b"\r\n\r\n"), "неверный offset res-body"
    body = dechunk(rest[offsets["res-body"]:])
    return status, headers, http_head, body


def content_length(head: bytes) -> int:
    for line in head.split(b"\r\n"):
        name, sep, value = line.partition(b":")
        if sep and name.lower() == b"content-length":
            return int(value)
    raise AssertionError("в head нет Content-Length")


# Вody без изменений 
class TestPassthrough:
    @pytest.mark.parametrize("body", [
        b"",
        b"plain text",
        b"\x00\xff\r\n\r\n" + bytes(range(256)),
        b"ENC",
        b"ENC2" + b"\x00" * 40,
        b"enc1" + b"\x00" * 40,
    ])
    def test_body_is_not_changed(self, server_port, body):
        head = make_head(len(body))
        status, _, res_head, res_body = parse_response(
            roundtrip(server_port, build_request(head, body)))
        assert status == 200
        assert res_body == body
        assert res_head == head

    def test_one_byte_chunks(self, server_port):
        body = bytes(range(256))
        head = make_head(len(body))
        request = build_request(head, body, chunk_sizes=[1] * len(body))
        status, _, res_head, res_body = parse_response(roundtrip(server_port, request))
        assert status == 200
        assert res_body == body
        assert res_head == head


# Расшифровка
class TestDecrypt:
    def test_roundtrip(self, server_port):
        plaintext = os.urandom(1024)
        body = encrypt_body(plaintext)
        head = make_head(len(body))
        status, _, res_head, res_body = parse_response(
            roundtrip(server_port, build_request(head, body)))
        assert status == 200
        assert res_body == plaintext
        assert res_head == make_head(len(plaintext))

    def test_empty_plaintext(self, server_port):
        body = encrypt_body(b"")
        assert len(body) == 32
        status, _, res_head, res_body = parse_response(
            roundtrip(server_port, build_request(make_head(len(body)), body)))
        assert status == 200
        assert res_body == b""
        assert content_length(res_head) == 0

    def test_binary_plaintext(self, server_port):
        plaintext = b"\r\n0\r\n\r\n\x00\xff" + bytes(range(256))
        body = encrypt_body(plaintext)
        status, _, _, res_body = parse_response(
            roundtrip(server_port, build_request(make_head(len(body)), body)))
        assert status == 200
        assert res_body == plaintext

    def test_other_headers_and_status_line_preserved(self, server_port):
        plaintext = os.urandom(64)
        body = encrypt_body(plaintext)
        head = (
            b"HTTP/1.1 206 Partial Content\r\n"
            b"X-Custom: keep-me\r\n"
            b"cOnTeNt-LeNgTh: " + str(len(body)).encode() + b"\r\n"
            b"Content-Type: application/x-unknown\r\n"
            b"\r\n"
        )
        status, _, res_head, res_body = parse_response(
            roundtrip(server_port, build_request(head, body)))
        assert status == 200
        assert res_body == plaintext
        lines = res_head.split(b"\r\n")
        assert lines[0] == b"HTTP/1.1 206 Partial Content"
        assert lines[1] == b"X-Custom: keep-me"
        assert lines[2] == b"cOnTeNt-LeNgTh: " + str(len(plaintext)).encode()
        assert lines[3] == b"Content-Type: application/x-unknown"
        assert res_head.endswith(b"\r\n\r\n")

    def test_large_body_with_random_chunks(self, server_port):
        plaintext = os.urandom(1024 * 1024)
        body = encrypt_body(plaintext)
        sizes = random_chunks(len(body), random.Random(7))
        request = build_request(make_head(len(body)), body, chunk_sizes=sizes)
        status, _, res_head, res_body = parse_response(roundtrip(server_port, request))
        assert status == 200
        assert res_body == plaintext
        assert content_length(res_head) == len(plaintext)

    def test_encapsulated_offset_is_recomputed(self, server_port):
        plaintext = b"12345"  # 5 байт, следовательно контейнер 37 байт и head становится короче
        body = encrypt_body(plaintext)
        head = make_head(len(body))
        status, headers, res_head, res_body = parse_response(
            roundtrip(server_port, build_request(head, body)))
        assert status == 200
        assert res_body == plaintext
        assert len(res_head) != len(head)
        assert f"res-body={len(res_head)}" in headers["encapsulated"]


# Нарезка на chunk'и
@pytest.mark.parametrize("mode", [
    "single", "one_byte", "random", "boundaries", "mixed", "upper_hex",
])
def test_chunk_boundaries_do_not_matter(server_port, mode):
    plaintext = os.urandom(300)
    body = encrypt_body(plaintext)
    if mode == "single":
        sizes = [len(body)]
    elif mode == "one_byte":
        sizes = [1] * len(body)
    elif mode == "random":
        sizes = random_chunks(len(body), random.Random(42))
    elif mode == "boundaries":
        sizes = [4, 12, len(body) - 32, 16]  # границы magic | nonce | ciphertext | tag
    elif mode == "mixed":
        sizes = [1, 2, 3, len(body) - 6]
    else:
        sizes = [7, len(body) - 7]
    request = build_request(make_head(len(body)), body, chunk_sizes=sizes,
                            upper_hex=(mode == "upper_hex"))
    status, _, res_head, res_body = parse_response(roundtrip(server_port, request))
    assert status == 200
    assert res_body == plaintext
    assert content_length(res_head) == len(plaintext)


def test_request_sent_in_small_pieces(server_port):
    """Парсер не должен зависеть от того, как запрос разбит на TCP-пакеты."""
    plaintext = os.urandom(64)
    body = encrypt_body(plaintext)
    request = build_request(make_head(len(body)), body, chunk_sizes=[1] * len(body))
    status, _, _, res_body = parse_response(roundtrip(server_port, request, piece_size=3))
    assert status == 200
    assert res_body == plaintext


# Ошибки
class TestErrors:
    @pytest.mark.parametrize("body", [
        b"ENC1",                    # только magic
        b"ENC1" + b"\x00" * 27,     # 31 байт: слишком короткий
        b"ENC1" + b"\x00" * 28,     # 32 байта: ошибка аутентификации
    ])
    def test_bad_container(self, server_port, body):
        status, _, _, _ = parse_response(
            roundtrip(server_port, build_request(make_head(len(body)), body)))
        assert 400 <= status < 500

    @pytest.mark.parametrize("index", [5, 20, -1])  # nonce, ciphertext, tag
    def test_corrupted_container(self, server_port, index):
        body = bytearray(encrypt_body(os.urandom(32)))
        body[index] ^= 0xFF
        status, _, _, _ = parse_response(
            roundtrip(server_port, build_request(make_head(len(body)), bytes(body))))
        assert 400 <= status < 500

    def test_server_keeps_working_after_error(self, server_port):
        bad = build_request(make_head(4), b"ENC1")
        assert 400 <= parse_response(roundtrip(server_port, bad))[0] < 500

        plaintext = os.urandom(50)
        body = encrypt_body(plaintext)
        status, _, _, res_body = parse_response(
            roundtrip(server_port, build_request(make_head(len(body)), body)))
        assert status == 200
        assert res_body == plaintext

    def test_unknown_service(self, server_port):
        request = build_request(make_head(3), b"abc", path="/other")
        assert parse_response(roundtrip(server_port, request))[0] == 404

    def test_wrong_method(self, server_port):
        request = build_request(make_head(3), b"abc", method="REQMOD")
        assert parse_response(roundtrip(server_port, request))[0] == 405

    def test_wrong_version(self, server_port):
        request = build_request(make_head(3), b"abc", version="ICAP/1.1")
        assert parse_response(roundtrip(server_port, request))[0] == 505

    def test_missing_encapsulated_header(self, server_port):
        head = make_head(3)
        request = build_request(head, b"abc")
        line = f"Encapsulated: res-hdr=0, res-body={len(head)}\r\n".encode()
        assert line in request
        assert parse_response(roundtrip(server_port, request.replace(line, b"")))[0] == 400

    def test_wrong_res_hdr_offset(self, server_port):
        request = build_request(make_head(3), b"abc").replace(b"res-hdr=0", b"res-hdr=5")
        assert parse_response(roundtrip(server_port, request))[0] == 400

    def test_bad_chunk_size(self, server_port):
        request = build_request(make_head(3), b"abc").replace(b"3\r\nabc\r\n", b"zz\r\nabc\r\n")
        assert parse_response(roundtrip(server_port, request))[0] == 400


# Протокол и конфигурация
def test_status_line_and_istag(server_port):
    raw = roundtrip(server_port, build_request(make_head(3), b"abc"))
    assert raw.startswith(b"ICAP/1.0 200 OK\r\n")
    _, headers, _, _ = parse_response(raw)
    assert headers["istag"].startswith('"') and len(headers["istag"]) > 2


def test_several_sequential_connections(server_port):
    for _ in range(3):
        plaintext = os.urandom(16)
        body = encrypt_body(plaintext)
        status, _, _, res_body = parse_response(
            roundtrip(server_port, build_request(make_head(len(body)), body)))
        assert status == 200
        assert res_body == plaintext


def test_load_key_validation(monkeypatch):
    monkeypatch.setenv("ICAP_AES_KEY_HEX", "not-a-hex")
    with pytest.raises(RuntimeError):
        icap_server.load_key()

    monkeypatch.setenv("ICAP_AES_KEY_HEX", "00" * 31)  # 31 байт, нужно 32
    with pytest.raises(RuntimeError):
        icap_server.load_key()

    monkeypatch.setenv("ICAP_AES_KEY_HEX", "00" * 32)
    assert icap_server.load_key() == bytes(32)