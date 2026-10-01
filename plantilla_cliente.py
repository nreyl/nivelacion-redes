"""
plantilla_cliente.py — ESQUELETO para TU cliente de AlpesPay.

La capa de transporte ya está resuelta: `ws_cliente.py` (que va junto a este
archivo) implementa WebSocket sobre TLS — handshake, framing y máscara — y te da
un canal para enviar y recibir BYTES:

    c = WSCliente("wss://<HOST>:<PUERTO>/")
    c.send_bytes(b"...")          # envías bytes
    respuesta = c.recv_bytes()    # recibes bytes (un mensaje)
    c.close()

Tu trabajo es implementar el PROTOCOLO: qué bytes mandar y cómo leer las
respuestas. Eso lo reconstruyes tú a partir de TU captura (Wireshark, filtro de
visualización `websocket`). Este archivo NO trae la solución: los identificadores
de servicio y de operación, los tamaños/orden de los campos y la firma los
deduces del tráfico.

No estás obligado a usar `ws_cliente.py`: puedes usar la librería que prefieras
(p. ej. `websocket-client`) o implementar tú mismo el handshake/framing sobre un
socket TLS. Lo único fijo es que se habla WebSocket sobre TLS.

Uso:
    python3 plantilla_cliente.py wss://<HOST>:<PUERTO>/
(HOST y PUERTO los ves en tu captura.)

Descifrado de TU propio tráfico: usa un Python con OpenSSL 1.1.1+ (no el LibreSSL
de fábrica de macOS) y define SSLKEYLOGFILE antes de ejecutar; `ws_cliente.py`
exporta las claves para Wireshark. Ver el manual (Subsistema de captura).
"""

import re
import struct  # empacar/desempacar enteros; el protocolo es big-endian -> usa ">"
import sys
import logging
import os

from ws_cliente import WSCliente

# ───────────────────────────────────── Datos ──────────────────────────────────
def _cargar_env(ruta=".env"):
    """Lee variables de un archivo .env local (que NO se sube al repo)."""
    try:
        with open(ruta) as f:
            for linea in f:
                linea = linea.strip()
                if linea and not linea.startswith("#") and "=" in linea:
                    k, v = linea.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())
    except FileNotFoundError:
        pass
    
    
URL_DEFAULT = "wss://alpespay.datoid.co:9010/"
_cargar_env()
USERNAME = os.environ.get("ALPES_USER", "equipoXX")  
PASSWORD = os.environ.get("ALPES_PIN", "XXXX") 


# Constantes del Protocolo
SERVICE_ID = b"AC"
HEADER_FORMAT = ">2sBBH"  # Big-endian: 2 bytes string, 1 byte char, 1 byte char, 2 bytes unsigned short
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # Equivale a 6 bytes

# Códigos de Operación (Request) — nombres segun el catalogo (op 0x07)
OP_ANNOUNCE= 0x01          # HELLO
OP_LOGIN = 0x02            # LOGIN
OP_CONSULT_BALANCE = 0x03  # SALDO
OP_CONSULT_HISTORY = 0x04  # EXTRACTO
OP_TRANSFERIR = 0x05       # TRANSFERIR (argumentos por determinar)
OP_ABONAR = 0x06           # ABONAR (abono de vale, argumentos por determinar)
OP_CATALOGO = 0x07         # CATALOGO
OP_TRANSFER = 0x08         # ENVIAR (la transferencia que ya dio token)
OP_AJUSTE = 0x09           # AJUSTE (rol: admin) — operacion dev/debug oculta
OP_ERROR = 0xEE

ANNOUNCE_MSG = b"alpespay-web"

# ───────────────────────────────────── Configuración de Logs ──────────────────────────────────
logger = logging.getLogger("alpespay_cliente")
logger.setLevel(logging.INFO)

# Patrón de formato unificado para todas las salidas del logger
format_log = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

# Configuración dual: guardar en archivo local y mostrar en consola
file_handler = logging.FileHandler("sesion_alpespay.log", encoding="utf-8")
file_handler.setFormatter(format_log)
logger.addHandler(file_handler)

# Configuración del manejador de visualización en vivo por consola
console_handler = logging.StreamHandler()
console_handler.setFormatter(format_log)
logger.addHandler(console_handler)

def hexdump(b: bytes) -> str:
    """Bytes -> 'aa bb cc ...' para inspeccionar respuestas mientras experimentas."""
    return " ".join(f"{x:02x}" for x in b)

# ───────────────────────────────────── Empaquetado y Parseo ──────────────────────────────────
def pack_frame(op: int, payload: bytes = b"", flags: int = 0) -> bytes:
    """
    Construye una trama binaria agregando la cabecera correspondiente de 6 bytes.
    Estructura generada:
      - SERVICE_ID (2 bytes): Identificador del servicio (ej. b"AC")
      - op (1 byte): Código de operación que se desea solicitar
      - flags (1 byte): Banderas de control adicionales
      - len (2 bytes): Longitud exacta del payload en formato Big-Endian
      - payload (N bytes): Datos o parámetros de la orden
    """
    return struct.pack(HEADER_FORMAT, SERVICE_ID, op, flags, len(payload)) + payload

class FrameParser:
    """
    Manejador de tramas (Handler / Parser de fragmentación de red).
    
    Este handler implementa un búfer interno acumulativo que:
      1. Acumula todos los bytes crudos que va recibiendo la red.
      2. Evalúa si el búfer tiene al menos el tamaño de la cabecera (HEADER_SIZE = 6 bytes).
      3. Lee la cabecera para determinar el tamaño exacto del payload esperado.
      4. Verifica si ya llegaron suficientes bytes en el búfer para completar esa trama.
      5. Extrae la trama completa (cabecera + payload), la remueve del búfer y la entrega 
         para su procesamiento, dejando el sobrante para el siguiente ciclo.
    """
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data: bytes):
        """
        Alimenta el búfer con nuevos bytes provenientes del WebSocket y extrae 
        todas las tramas completas que se alcancen a formar.
        
        Retorna:
            Una lista de tuplas con las tramas listas: [(op, flags, payload), ...]
        """
        if data:
            self.buffer.extend(data)
            
        extracted_frames = []
        
        # Bucle para extraer tantas tramas completas como contenga actualmente el búfer
        while len(self.buffer) >= HEADER_SIZE:
            # Desempaquetamos los primeros 6 bytes de la cabecera
            _signature, op, flags, length = struct.unpack(
                HEADER_FORMAT, bytes(self.buffer[:HEADER_SIZE])
            )
            
            # Calculamos el tamaño total que debe ocupar esta trama en bytes
            total_frame_size = HEADER_SIZE + length
            
            # Si el búfer aún no tiene todos los bytes de esta trama, detenemos 
            # la extracción y esperamos a que lleguen más datos en el siguiente recv.
            if len(self.buffer) < total_frame_size:
                break
                
            # Extraemos el payload correspondiente a la longitud indicada en la cabecera
            payload = bytes(self.buffer[HEADER_SIZE:total_frame_size])
            
            # Purgamos del búfer interno los bytes correspondientes a la trama ya procesada
            del self.buffer[:total_frame_size]
            
            # Añadimos la trama limpia a la lista de salida
            extracted_frames.append((op, flags, payload))
            
        return extracted_frames

def scan_token(op: int, payload: bytes):
    """Detecta tokens de verificacion, que vienen con el prefijo 'TKN:'."""
    i = payload.find(b"TKN:")
    if i != -1:
        tok = payload[i+4:].decode("ascii", "replace").strip()
        logger.warning(">>> TOKEN DE VERIFICACION (op 0x%02x): %s", op, tok)
    
# ───────────────────────────────────── Clase del Cliente ──────────────────────────────────
class AlpesPayClient:
    """Gestiona la conexión y la ejecución de operaciones contra el servicio de cuentas de AlpesPay."""
    def __init__(self, url: str):
        self.ws = WSCliente(url)
        self.parser = FrameParser()
        self.token = None
        self.account = None
        logger.info("Conectado a %s", url)

    def close(self):
        """Cierra la conexión WebSocket subyacente de manera limpia."""
        self.ws.close()

    def _rt(self, op: int, payload: bytes = b""):
        """
        Método central de Transacción / Round-Trip (_rt):
          1. Empaqueta la orden con su respectiva cabecera binaria.
          2. Envía los bytes a través del WebSocket.
          3. Entra en un bucle de lectura escuchando las respuestas del servidor.
          4. Alimenta al `FrameParser` para garantizar que no afecten problemas de fragmentación.
          5. Valida si la respuesta corresponde a un error del servidor (OP_ERROR = 0xEE)
             o si trae consigo datos legítimos.
        """
        raw = pack_frame(op, payload)
        logger.info("TX op=0x%02x  %s", op, hexdump(raw))
        self.ws.send_bytes(raw)
        
        while True:
            # Recibimos bloques de bytes del socket y dejamos que el parser los ordene
            raw_response = self.ws.recv_bytes()
            frames = self.parser.feed(raw_response)
            
            for (rop, _flags, pl) in frames:
                logger.info("RX op=0x%02x len=%d  %s", rop, len(pl), hexdump(pl))
                scan_token(rop, pl)
                
                # Manejo estandarizado de códigos de error reportados por el servidor
                if rop == OP_ERROR:
                    err_code = pl[0] if pl else -1
                    err_msg = pl[1:].decode("utf-8", "replace")
                    logger.warning("ERROR 0x%02x: %s", err_code, err_msg)
            
            # Retornamos las tramas tan pronto como se complete un ciclo de intercambio válido
            if frames:
                return frames

    def announce(self):
        """Envía el mensaje inicial de anuncio para establecer compatibilidad con el servidor."""
        return self._rt(OP_ANNOUNCE, ANNOUNCE_MSG)

    def login(self, username: str, password: str):
        """
        Realiza la autenticación enviando el usuario seguido de un byte nulo (b'\\x00') 
        y la contraseña. Parsea la respuesta para extraer y guardar el token de sesión (4 bytes) 
        y el número de cuenta asociado (4 bytes en formato Big-Endian).
        """
        op, _f, pl = self._rt(OP_LOGIN, username.encode() + b"\x00" + password.encode())[0]
        if op == OP_ERROR:
            raise SystemExit("Login fallido: revisa USERNAME/PASSWORD.")
        self.token = pl[:4]
        self.account = int.from_bytes(pl[4:8], "big")
        logger.info("Sesión OK. token=%s cuenta=%d", self.token.hex(), self.account)

    def get_balance(self) -> int:
        """Consulta el saldo actual de la cuenta autenticada enviando el token y leyendo 8 bytes en centavos."""
        op, _f, pl = self._rt(OP_CONSULT_BALANCE, self.token)[0]
        cents = int.from_bytes(pl[:8], "big")
        logger.info("Saldo = %d centavos ($%.2f)", cents, cents / 100)
        return cents

    def get_history(self):
        """Obtiene el historial de transacciones utilizando el token de sesión actual."""
        return self._rt(OP_CONSULT_HISTORY, self.token)[0]

    def get_catalog(self):
        """Solicita al servidor (op 0x07) la lista completa de operaciones disponibles."""
        return self._rt(OP_CATALOGO, self.token)[0]

    def transfer(self, destination: str, amount_cents: int) -> str:
        """
        Ejecuta una transferencia de fondos (op 0x08 ENVIAR) armando el payload con:
          - Token de sesión (4 bytes)
          - Monto en centavos (8 bytes, enteros Big-Endian)
          - Cuenta destino (String codificado en bytes, p. ej. '@equipo17')
        La respuesta trae el saldo nuevo (8 bytes) y un token de verificación (8 ASCII).
        """
        pl = self.token + amount_cents.to_bytes(8, "big") + destination.encode()
        op, _f, r = self._rt(OP_TRANSFER, pl)[0]
        if op == OP_ERROR:
            return None
        balance = int.from_bytes(r[:8], "big")
        tok = r[8:].decode("ascii", "replace") if len(r) > 8 else None
        logger.info("Transferencia OK. saldo=$%.2f  token=%s", balance / 100, tok)
        return tok

    # ─────────── Utilidades para tantear las operaciones que piden argumentos ──────────
    def probe(self, op: int, extra: bytes = b""):
        """
        Función de tanteo: envía 'token + extra' a cualquier operación y devuelve 
        la respuesta cruda. Sirve para descubrir qué payload esperan las operaciones 
        05/06/09 leyendo el mensaje de error que regresa el servidor.
        
        Ejemplos:
            c.probe(0x06, (500000).to_bytes(8, "big"))   # ABONAR con monto $5000
            c.probe(0x09)                                 # AJUSTE a secas
        """
        return self._rt(op, self.token + extra)

    def abonar(self, amount_cents: int):
        """
        06 ABONAR (abono de vale): primer intento con 'token + monto(8)'.
        Si devuelve 'argumentos invalidos', ajusta el formato del payload.
        """
        return self._rt(OP_ABONAR, self.token + amount_cents.to_bytes(8, "big"))

    def transferir(self, account: int, amount_cents: int):
        """
        05 TRANSFERIR: primer intento con 'token + cuenta(4) + monto(8)'.
        Variante de la transferencia que usa número de cuenta en vez de @usuario.
        Ajusta tamaños/orden según el error que regrese.
        """
        pl = self.token + account.to_bytes(4, "big") + amount_cents.to_bytes(8, "big")
        return self._rt(OP_TRANSFERIR, pl)

    def ajuste(self, extra: bytes = b"", flags: int = 0):
        """
        09 AJUSTE (rol: admin): operación oculta dev/debug. Permite variar el
        payload 'extra' y el byte de 'flags' (por si el rol admin se activa ahí).
        """
        raw = pack_frame(OP_AJUSTE, self.token + extra, flags)
        logger.info("TX op=0x%02x flags=0x%02x  %s", OP_AJUSTE, flags, hexdump(raw))
        self.ws.send_bytes(raw)
        while True:
            frames = self.parser.feed(self.ws.recv_bytes())
            for (rop, _f, pl) in frames:
                logger.info("RX op=0x%02x len=%d  %s", rop, len(pl), hexdump(pl))
                scan_token(rop, pl)
                if rop == OP_ERROR:
                    logger.warning("ERROR 0x%02x: %s", pl[0] if pl else -1,
                                   pl[1:].decode("utf-8", "replace"))
            if frames:
                return frames

    def enumerate_ops(self, ops=None):
        """
        Función de descubrimiento (Fuzzing / Escaneo pasivo y activo):
        Barre de forma automatizada identificadores de operación desconocidos o no documentados 
        dentro de un rango determinado (ej. 0x01 a 0x3F) enviando el token activo, 
        lo que permite descubrir endpoints ocultos (como abonos, funciones de depuración o devales).
        """
        known = {OP_ANNOUNCE, OP_LOGIN, OP_CONSULT_BALANCE, OP_CONSULT_HISTORY, OP_TRANSFER}
        ops = ops or [o for o in range(0x01, 0x40) if o not in known]
        for op in ops:
            logger.info("--- probando op 0x%02x ---", op)
            try:
                self._rt(op, self.token or b"")
            except Exception as e:
                logger.info("op 0x%02x -> %r", op, e)


def main(url: str, enum: bool = False) -> None:
    client = AlpesPayClient(url)
    try:
        client.announce()
        client.login(USERNAME, PASSWORD)
        client.get_balance()
        client.get_history()
        client.get_catalog()
        
        # Descomenta la siguiente línea si deseas hacer una transferencia de prueba
        # client.transfer("@equipo17", 100)
        
        if enum:
            client.enumerate_ops()
    finally:
        client.close()


if __name__ == "__main__":
    args = sys.argv[1:]
    enum = "--enum" in args
    args = [a for a in args if a != "--enum"]
    url = args[0] if args else URL_DEFAULT
    main(url, enum=enum)


# ════════════════════════════════════════════════════════════════════════════
# SERVICIO DE VALES (firma "AV", mismo canal 9010, NO usa la cabecera AC).
#
#   Emitir:  "AV" + 0x01 + cuenta(4)
#            -> "AV" + 0x81 + cuenta(4) + monto(8) + serial(4) + crc(2)
#   Abonar:  op 0x06 del servicio de cuentas, payload = token + bloque_del_vale
#            donde bloque_del_vale = cuenta(4) + monto(8) + serial(4) + crc(2)
#
# Checksum roto a partir de 46 vales capturados (sin clave, como decia el manual):
#   CRC-16/CCITT (poly=0x1021, sin reflexion) XOR una constante de cuenta.
#   La constante CRC_CONST_CUENTA es ESPECIFICA de la cuenta (aqui, 1023 -> 0x7143).
#   Para otra cuenta habria que recalcularla con sus propios vales.
# ════════════════════════════════════════════════════════════════════════════
CRC_CONST_CUENTA = 0x7143   # <-- especifico de la cuenta 1023 (equipo22)

def crc16_ccitt(data: bytes, poly: int = 0x1021) -> int:
    reg = 0
    for b in data:
        reg ^= (b << 8)
        for _ in range(8):
            reg = ((reg << 1) ^ poly) & 0xFFFF if (reg & 0x8000) else (reg << 1) & 0xFFFF
    return reg

def forjar_vale(cuenta: int, monto_centavos: int, serial: bytes) -> bytes:
    """
    Construye un bloque de vale VALIDO sin pedirlo al servidor, calculando el
    checksum nosotros mismos. Demuestra que el checksum sin clave es falsificable.
    serial: 4 bytes a eleccion (cualquiera que el servidor no haya emitido ya).
    """
    cuerpo = cuenta.to_bytes(4, "big") + monto_centavos.to_bytes(8, "big") + serial
    cks = crc16_ccitt(cuerpo) ^ CRC_CONST_CUENTA
    return cuerpo + cks.to_bytes(2, "big")

def _extiende_vales():
    def emitir_vale(self, cuenta: int):
        """Pide un vale real al servicio de vales (firma AV)."""
        self.ws.send_bytes(b"AV\x01" + cuenta.to_bytes(4, "big"))
        resp = self.ws.recv_bytes()
        logger.info("VALE emitido: %s", resp.hex())
        return resp  # "AV"+0x81+cuenta+monto+serial+crc

    def abonar_vale(self, bloque_vale: bytes):
        """Abona un bloque de vale (real o forjado) via op 0x06 del servicio de cuentas."""
        return self._rt(OP_ABONAR, self.token + bloque_vale)

    AlpesPayClient.emitir_vale = emitir_vale
    AlpesPayClient.abonar_vale = abonar_vale

_extiende_vales()