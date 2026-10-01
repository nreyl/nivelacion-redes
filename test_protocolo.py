"""
test_protocolo.py — Verifica la logica del protocolo SIN tocar el servidor.

Compara tu pack_frame / FrameParser contra los bytes REALES de la captura.
Si todo pasa, tu empaquetado y parseo estan correctos.

Correlo en la misma carpeta que plantilla_cliente.py y ws_cliente.py:
    python3 test_protocolo.py

(Solo importa funciones; NO abre ninguna conexion.)
"""
from plantilla_cliente import pack_frame, FrameParser

def check(nombre, cond):
    print(("OK  " if cond else "FALLA ") + nombre)
    assert cond, nombre

# --- 1. pack_frame reproduce exactamente los mensajes capturados -------------
login = pack_frame(0x02, b"equipo22" + b"\x00" + b"0020").hex()
check("login == frame 107", login == "41430200000d65717569706f32320030303230")

pl = bytes.fromhex("2665d200") + (100000).to_bytes(8, "big") + b"@equipo17"
transfer = pack_frame(0x08, pl).hex()
check("transfer == frame 803",
      transfer == "4143080000152665d20000000000000186a04065717569706f3137")

# --- 2. FrameParser separa bien las tramas ----------------------------------
p = FrameParser()
# respuesta de login (frame 108)
frames = p.feed(bytes.fromhex("4143820000082665d200000003ff"))
op, flags, payload = frames[0]
check("login: una sola trama", len(frames) == 1)
check("login: op = 0x82", op == 0x82)
check("login: token = 2665d200", payload[:4].hex() == "2665d200")
check("login: cuenta = 1023", int.from_bytes(payload[4:8], "big") == 1023)

# saldo (frame 113)
op, _f, payload = p.feed(bytes.fromhex("414383000008000000000023bff4"))[0]
check("saldo = $23429.00", int.from_bytes(payload[:8], "big") == 2342900)

# transfer (frame 804) -> saldo nuevo + token de verificacion
op, _f, payload = p.feed(bytes.fromhex("41438800001000000000002239544150314d484e584a"))[0]
check("transfer: saldo nuevo = $22429.00", int.from_bytes(payload[:8], "big") == 2242900)
check("transfer: TOKEN = AP1MHNXJ", payload[8:].decode("ascii") == "AP1MHNXJ")

# --- 3. FRAGMENTACION: una trama partida en dos lecturas --------------------
p = FrameParser()
entero = bytes.fromhex("4143820000082665d200000003ff")
check("mitad 1 no entrega trama", p.feed(entero[:4]) == [])   # llega incompleta
frames = p.feed(entero[4:])                                   # llega el resto
check("al completar, sale 1 trama", len(frames) == 1 and frames[0][0] == 0x82)

# --- 4. CONCATENACION: dos tramas en una sola lectura -----------------------
p = FrameParser()
dos = bytes.fromhex("414383000008000000000023bff4") + \
      bytes.fromhex("4143820000082665d200000003ff")
frames = p.feed(dos)
check("dos tramas concatenadas -> 2", len(frames) == 2)

print("\nTODO BIEN: el protocolo esta correctamente implementado.")