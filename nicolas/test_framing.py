#!/usr/bin/env python3
"""
test_framing.py — Prueba local del transporte ws_cliente.py SIN tocar el laboratorio.

Verifica el framing WebSocket (enmascarado del cliente, longitudes de 7/16/64 bits,
round-trip send/recv y reensamblado de fragmentos). No abre ninguna conexión de red.

Uso:  python3 nicolas/test_framing.py
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ws_cliente import WSCliente, _OP_BIN  # noqa: E402


def _instancia_sin_conectar():
    c = object.__new__(WSCliente)

    class FakeSock:
        def __init__(self):
            self.sent = b""

        def sendall(self, b):
            self.sent += b

    c.sock = FakeSock()
    c._buf = b""
    return c


def _decode_client_frame(data):
    b1, b2 = data[0], data[1]
    i = 2
    assert b1 & 0x80, "FIN debe ser 1"
    assert b2 & 0x80, "el cliente debe enmascarar"
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack(">H", data[i:i + 2])[0]; i += 2
    elif length == 127:
        length = struct.unpack(">Q", data[i:i + 8])[0]; i += 8
    mask = data[i:i + 4]; i += 4
    payload = bytes(b ^ mask[j % 4] for j, b in enumerate(data[i:i + length]))
    return b1 & 0x0F, payload


def _server_frame(payload, opcode=_OP_BIN):
    b1 = 0x80 | opcode
    n = len(payload)
    h = bytearray([b1])
    if n < 126:
        h.append(n)
    elif n < 65536:
        h.append(126); h += struct.pack(">H", n)
    else:
        h.append(127); h += struct.pack(">Q", n)
    return bytes(h) + payload  # el servidor NO enmascara


def main():
    c = _instancia_sin_conectar()
    for size in (5, 200, 70000):  # cubre longitudes de 7, 16 y 64 bits
        payload = os.urandom(size)
        c.sock.sent = b""
        c.send_bytes(payload)
        op, dec = _decode_client_frame(c.sock.sent)
        assert op == _OP_BIN and dec == payload, f"send falló size={size}"
        c._buf = _server_frame(payload)
        assert c.recv_bytes() == payload, f"recv falló size={size}"
        print(f"OK size={size}: round-trip correcto")

    p1, p2 = b"hola-", b"mundo"
    c._buf = bytes([0x02, len(p1)]) + p1 + bytes([0x80, len(p2)]) + p2
    assert c.recv_bytes() == p1 + p2, "fragmentación falló"
    print("OK fragmentación: reensamblado correcto")
    print("\nTODOS LOS TESTS DE FRAMING PASARON")


if __name__ == "__main__":
    main()
