#!/usr/bin/env python3
"""
cliente_cuentas.py — Cliente del SERVICIO DE CUENTAS de AlpesPay (parte de Nicolás).

Cubre los resultados asignados a Nicolás:
    R1  anuncio del cliente
    R2  inicio de sesión  -> devuelve <TOKEN> (id de sesión)
    R3  consulta de saldo
    R7  dev/debug: transferencia + validación del origen frente al titular del token

Diseño honesto: el manual dice explícitamente que los identificadores de servicio
y operación, y el tamaño/orden de los campos, NO están documentados y se DEDUCEN de
la captura (usa nicolas/extraer_frames.py). Por eso todo lo que hay que leer de la
captura está arriba, como constantes marcadas  # <-- CONFIRMAR EN CAPTURA.
Mientras valgan None, el cliente avisa en vez de inventar bytes.

Transporte: usa ws_cliente.WSCliente (WebSocket sobre TLS), el módulo que entrega
el curso junto a plantilla_cliente.py. Colócalo accesible en el PYTHONPATH.

Uso:
    python3 nicolas/cliente_cuentas.py wss://<HOST>:9010/ anuncio
    python3 nicolas/cliente_cuentas.py wss://<HOST>:9010/ login   --usuario U --pin 1234
    python3 nicolas/cliente_cuentas.py wss://<HOST>:9010/ saldo   --token <hex>
    python3 nicolas/cliente_cuentas.py wss://<HOST>:9010/ probar-op --op 0x?? --payload <hex>
    python3 nicolas/cliente_cuentas.py wss://<HOST>:9010/ test-origen --token <hex> --origen <cuenta> --destino <cuenta> --centavos 1

ÉTICA / ALCANCE: solo tu cuenta y el laboratorio del curso. `test-origen` NO usa
credenciales de nadie: manda una transferencia con un ORIGEN distinto usando TU
token y observa si el servidor la rechaza. El hallazgo es la RESPUESTA del servidor,
no mover dinero de otra cuenta.
"""
import argparse
import struct
import sys

try:
    from ws_cliente import WSCliente
except ImportError:
    WSCliente = None  # se avisa en main(); permite deducir sin el módulo aún

# ─────────────────────────────────────────────────────────────────────────────
# PARÁMETROS QUE SE DEDUCEN DE LA CAPTURA  (rellenar con extraer_frames.py)
# ─────────────────────────────────────────────────────────────────────────────
SERVICIO_CUENTAS = None   # <-- CONFIRMAR EN CAPTURA: byte(s) que marcan "cuentas"

# Identificadores de operación (op_id). Ajustar tras alinear la captura.
OP_ANUNCIO   = None       # <-- CONFIRMAR EN CAPTURA
OP_LOGIN     = None       # <-- CONFIRMAR EN CAPTURA
OP_SALDO     = None       # <-- CONFIRMAR EN CAPTURA
OP_TRANSFERIR = None      # <-- CONFIRMAR EN CAPTURA (la que indica cuenta ORIGEN)

# Forma de la cabecera del servicio de cuentas. Hipótesis a validar byte a byte:
#   service_id | op_id | flags | length(N bytes, big-endian) | contenido
# Ajusta los anchos a lo que muestre la captura.
ANCHO_SERVICIO = 1        # <-- CONFIRMAR EN CAPTURA (bytes)
ANCHO_OP       = 1        # <-- CONFIRMAR EN CAPTURA
ANCHO_FLAGS    = 1        # <-- CONFIRMAR EN CAPTURA
ANCHO_LONGITUD = 2        # <-- CONFIRMAR EN CAPTURA (p. ej. 2 -> ">H", 4 -> ">I")


def _u(width: int, value: int) -> bytes:
    """Entero big-endian de `width` bytes."""
    return value.to_bytes(width, "big")


def _falta(*nombres: str) -> None:
    faltan = [n for n in nombres if globals().get(n) is None]
    if faltan:
        sys.exit(
            "Faltan parámetros por deducir de la captura: "
            + ", ".join(faltan)
            + "\nUsa  python3 nicolas/extraer_frames.py <pcap>  y rellena las "
              "constantes marcadas '# <-- CONFIRMAR EN CAPTURA' arriba."
        )


def construir_trama(op_id: int, contenido: bytes, flags: int = 0) -> bytes:
    """Arma una trama del servicio de cuentas con la cabecera hipotética."""
    _falta("SERVICIO_CUENTAS")
    cab = _u(ANCHO_SERVICIO, SERVICIO_CUENTAS) + _u(ANCHO_OP, op_id) + _u(ANCHO_FLAGS, flags)
    cab += _u(ANCHO_LONGITUD, len(contenido))
    return cab + contenido


def leer_trama(data: bytes) -> dict:
    """Desarma una respuesta segun la cabecera hipotetica. Devuelve dict crudo."""
    i = 0
    def take(w):
        nonlocal i
        v = int.from_bytes(data[i:i + w], "big"); i += w
        return v
    servicio = take(ANCHO_SERVICIO)
    op = take(ANCHO_OP)
    flags = take(ANCHO_FLAGS)
    longitud = take(ANCHO_LONGITUD)
    contenido = data[i:i + longitud]
    return {"servicio": servicio, "op": op, "flags": flags,
            "longitud": longitud, "contenido": contenido, "cruda": data}


def hexdump(b: bytes) -> str:
    return b.hex(" ")


def _intercambio(c, trama: bytes) -> bytes:
    print("->", hexdump(trama))
    c.send_bytes(trama)
    resp = c.recv_bytes()
    print("<-", hexdump(resp))
    return resp


# ── R1: anuncio del cliente ─────────────────────────────────────────────────
def anuncio(c) -> bytes:
    _falta("OP_ANUNCIO")
    # El contenido exacto del anuncio se deduce de la captura (versión/hello).
    contenido = b""   # <-- CONFIRMAR EN CAPTURA
    return _intercambio(c, construir_trama(OP_ANUNCIO, contenido))


# ── R2: inicio de sesión -> token ───────────────────────────────────────────
def login(c, usuario: str, pin: str) -> bytes:
    _falta("OP_LOGIN")
    # Orden/tamaño de usuario y PIN: deducir de la captura. Hipótesis:
    #   [len usuario][usuario...][len pin][pin...]   (ajústalo a lo observado)
    u = usuario.encode()
    p = pin.encode()
    contenido = bytes([len(u)]) + u + bytes([len(p)]) + p   # <-- CONFIRMAR EN CAPTURA
    resp = _intercambio(c, construir_trama(OP_LOGIN, contenido))
    token = leer_trama(resp)["contenido"]   # el <TOKEN> viene en el contenido
    print("TOKEN (id de sesión):", hexdump(token))
    return token


# ── R3: consulta de saldo ───────────────────────────────────────────────────
def saldo(c, token: bytes) -> int:
    _falta("OP_SALDO")
    resp = _intercambio(c, construir_trama(OP_SALDO, token))
    cont = leer_trama(resp)["contenido"]
    # El saldo se expresa en centavos, big-endian. Ancho a confirmar (>q típico).
    centavos = int.from_bytes(cont, "big") if cont else 0   # <-- CONFIRMAR EN CAPTURA
    print(f"Saldo: {centavos} centavos = {centavos/100:.2f}")
    return centavos


# ── R7: transferencia + validación de origen ────────────────────────────────
def transferir(c, token: bytes, origen: str, destino: str, centavos: int) -> bytes:
    _falta("OP_TRANSFERIR")
    # Orden/tamaño de origen, destino y monto: deducir de la captura.
    o, d = origen.encode(), destino.encode()
    contenido = (token
                 + bytes([len(o)]) + o
                 + bytes([len(d)]) + d
                 + struct.pack(">q", centavos))   # <-- CONFIRMAR EN CAPTURA
    return _intercambio(c, construir_trama(OP_TRANSFERIR, contenido))


def test_origen(c, token: bytes, origen: str, destino: str, centavos: int) -> None:
    """
    Prueba la 'validación del origen frente al titular del token' (dev/debug).
    Envía la transferencia con un ORIGEN distinto al propio usando TU token y
    reporta la respuesta del servidor. NO usa credenciales de otra cuenta.
    El resultado del reto ES el comportamiento observado (¿rechaza o acepta?).
    """
    print("[R7] Probando validación de origen con origen =", origen,
          "(usando TU propio token)")
    resp = transferir(c, token, origen, destino, centavos)
    print("[R7] Respuesta del servidor arriba. Registra el token de verificación "
          "que emita y anota si aceptó o rechazó el origen ajeno.")
    return resp


def probar_op(c, op_id: int, payload: bytes) -> bytes:
    """Sondea una operación no listada (dev/debug) por su identificador."""
    return _intercambio(c, construir_trama(op_id, payload))


def main() -> None:
    ap = argparse.ArgumentParser(description="Cliente del servicio de cuentas de AlpesPay.")
    ap.add_argument("url", help="wss://<HOST>:9010/")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("anuncio")
    p = sub.add_parser("login");  p.add_argument("--usuario", required=True); p.add_argument("--pin", required=True)
    p = sub.add_parser("saldo");  p.add_argument("--token", required=True)
    p = sub.add_parser("transferir")
    p.add_argument("--token", required=True); p.add_argument("--origen", required=True)
    p.add_argument("--destino", required=True); p.add_argument("--centavos", type=int, required=True)
    p = sub.add_parser("test-origen")
    p.add_argument("--token", required=True); p.add_argument("--origen", required=True)
    p.add_argument("--destino", required=True); p.add_argument("--centavos", type=int, default=1)
    p = sub.add_parser("probar-op")
    p.add_argument("--op", required=True, help="id de operación, p. ej. 0x1f o 31")
    p.add_argument("--payload", default="", help="contenido en hex, p. ej. 'aabb'")

    args = ap.parse_args()

    if WSCliente is None:
        sys.exit("No encuentro ws_cliente.py (lo entrega el curso). Colócalo en el "
                 "PYTHONPATH o junto a este archivo antes de conectar.")

    c = WSCliente(args.url)
    try:
        if args.cmd == "anuncio":
            anuncio(c)
        elif args.cmd == "login":
            login(c, args.usuario, args.pin)
        elif args.cmd == "saldo":
            saldo(c, bytes.fromhex(args.token))
        elif args.cmd == "transferir":
            transferir(c, bytes.fromhex(args.token), args.origen, args.destino, args.centavos)
        elif args.cmd == "test-origen":
            test_origen(c, bytes.fromhex(args.token), args.origen, args.destino, args.centavos)
        elif args.cmd == "probar-op":
            probar_op(c, int(args.op, 0), bytes.fromhex(args.payload) if args.payload else b"")
    finally:
        c.close()


if __name__ == "__main__":
    main()
