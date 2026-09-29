"""
ws_cliente.py — Capa de transporte WebSocket sobre TLS para AlpesPay.

Resuelve TLS + handshake WebSocket + framing, y expone un canal de BYTES:

    c = WSCliente("wss://alpespay.datoid.co:9010/")
    c.send_bytes(b"...")          # envía un mensaje binario
    resp = c.recv_bytes()         # recibe un mensaje (bytes)
    c.close()

Sobre este canal se implementa el protocolo deducido de la captura
(ver nicolas/cliente_cuentas.py). Este módulo NO conoce el protocolo.

Exportación de claves TLS: si la variable de entorno SSLKEYLOGFILE está definida
y el intérprete se enlaza con OpenSSL 1.1.1+, las claves de sesión se escriben ahí
para que Wireshark descifre TU propio tráfico. El Python de fábrica de macOS usa
LibreSSL y NO exporta claves: usa uno de Homebrew (/opt/homebrew/bin/python3).

Implementación autocontenida (sin dependencias externas), conforme a RFC 6455:
las tramas cliente->servidor van enmascaradas, enteros big-endian.
"""
import base64
import os
import socket
import ssl
import struct
import sys
from urllib.parse import urlparse

# Opcodes WebSocket (RFC 6455 §5.2)
_OP_CONT = 0x0
_OP_TEXT = 0x1
_OP_BIN = 0x2
_OP_CLOSE = 0x8
_OP_PING = 0x9
_OP_PONG = 0xA


class WSCliente:
    def __init__(self, url: str, timeout: float = 15.0):
        u = urlparse(url)
        if u.scheme != "wss":
            raise ValueError("Solo se soporta wss:// (WebSocket sobre TLS).")
        self.host = u.hostname
        self.port = u.port or 443
        self.path = u.path or "/"
        if u.query:
            self.path += "?" + u.query

        raw = socket.create_connection((self.host, self.port), timeout=timeout)

        ctx = ssl.create_default_context()
        # Laboratorio con certificado propio: no validamos cadena/nombre (como el
        # navegador con --ignore-certificate-errors del script de captura).
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Exportar claves de sesión para descifrar la propia captura, si se puede.
        keylog = os.environ.get("SSLKEYLOGFILE")
        if keylog:
            if hasattr(ctx, "keylog_filename"):
                ctx.keylog_filename = keylog
            else:
                print("[ws_cliente] Aviso: este Python no soporta keylog "
                      "(¿LibreSSL?); no se exportarán claves TLS.", file=sys.stderr)

        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        self._buf = b""  # bytes TLS leídos y aún no consumidos por el framer
        self._handshake()

    # ── Handshake HTTP Upgrade ───────────────────────────────────────────────
    def _handshake(self) -> None:
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self.sock.sendall(req.encode())

        # Leer cabeceras HTTP hasta \r\n\r\n
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Conexión cerrada durante el handshake WebSocket.")
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].decode(errors="replace")
        if "101" not in status:
            raise ConnectionError(f"Handshake WebSocket falló: {status}")
        self._buf = rest  # datos que ya llegaron tras el handshake

    # ── Lectura de bytes TLS con buffer ──────────────────────────────────────
    def _read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("Conexión cerrada por el servidor.")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    # ── Enviar un mensaje binario (una sola trama, FIN=1, enmascarada) ───────
    def send_bytes(self, payload: bytes) -> None:
        self._send_frame(_OP_BIN, payload)

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        b1 = 0x80 | opcode  # FIN=1
        header = bytearray([b1])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)  # MASK=1
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        mask = os.urandom(4)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    # ── Recibir un mensaje (reensambla fragmentos, atiende ping/close) ───────
    def recv_bytes(self) -> bytes:
        message = b""
        while True:
            b1, b2 = self._read_exact(2)
            fin = b1 & 0x80
            opcode = b1 & 0x0F
            masked = b2 & 0x80
            length = b2 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if masked else b""
            data = self._read_exact(length)
            if masked:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))

            if opcode == _OP_CLOSE:
                self._safe_close_frame()
                raise ConnectionError("El servidor cerró la conexión (close frame).")
            if opcode == _OP_PING:
                self._send_frame(_OP_PONG, data)
                continue
            if opcode == _OP_PONG:
                continue

            message += data
            if fin:
                return message

    def _safe_close_frame(self) -> None:
        try:
            self._send_frame(_OP_CLOSE, b"")
        except Exception:
            pass

    def close(self) -> None:
        self._safe_close_frame()
        try:
            self.sock.close()
        except Exception:
            pass
