#!/usr/bin/env python3
"""
extraer_frames.py — Herramienta de DEDUCCIÓN (parte de Nicolás).

Lee el pcap YA DESCIFRADO (el que produce tools/capturar-mac.sh) y saca cada
trama WebSocket en hex, con su dirección (cliente->servidor o servidor->cliente),
para poder alinear el protocolo byte a byte.

No habla con el servidor: solo analiza tu propia captura. Requiere `tshark`
(viene con Wireshark).

Uso:
    python3 nicolas/extraer_frames.py /tmp/alpes_captura.pcap
    python3 nicolas/extraer_frames.py /tmp/alpes_captura.pcap --keylog ~/alpes_keys.log

Salida: una línea por trama:
    #<frame>  <DIR>  len=<n>  <bytes en hex>
DIR = C>S (cliente->servidor)  o  S>C (servidor->cliente).

Pistas para leer el resultado (del manual):
  • Los primeros bytes identifican el SERVICIO destino (cuentas vs. vales).
  • Todo entero es big-endian.
  • Empieza por el mensaje más corto y repetido y alinéalo.
  • El <TOKEN> del login se repite sin cambios en las operaciones siguientes.
"""
import argparse
import shutil
import subprocess
import sys


def find_tshark() -> str:
    en_path = shutil.which("tshark")
    if en_path:
        return en_path
    app = "/Applications/Wireshark.app/Contents/MacOS/tshark"
    import os
    if os.path.exists(app):
        return app
    sys.exit("No encontré 'tshark'. Instala Wireshark: brew install --cask wireshark")


def main() -> None:
    ap = argparse.ArgumentParser(description="Extrae tramas WebSocket de un pcap descifrado.")
    ap.add_argument("pcap", help="ruta al .pcap (p. ej. /tmp/alpes_captura.pcap)")
    ap.add_argument("--keylog", help="archivo SSLKEYLOGFILE, si el pcap aún no está descifrado")
    ap.add_argument("--puerto", default="9010", help="puerto del laboratorio (por omisión 9010)")
    args = ap.parse_args()

    tshark = find_tshark()
    cmd = [tshark, "-r", args.pcap, "-Y", "websocket"]
    if args.keylog:
        cmd += ["-o", f"tls.keylog_file:{args.keylog}"]
    cmd += [
        "-T", "fields",
        "-e", "frame.number",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "websocket.payload",   # datos de la trama WS, en hex
        "-E", "separator=|",
    ]

    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as e:
        sys.exit(f"tshark falló:\n{e.stderr}")

    n = 0
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) < 4:
            continue
        frame, srcport, dstport, payload = parts[0], parts[1], parts[2], parts[3]
        if not payload:
            continue
        raw = payload.replace(":", "").replace(" ", "")
        try:
            data = bytes.fromhex(raw)
        except ValueError:
            continue
        # El servidor escucha en args.puerto: si el destino es ese puerto, va del cliente.
        direction = "C>S" if dstport == args.puerto else "S>C"
        print(f"#{frame:>5}  {direction}  len={len(data):>4}  {data.hex(' ')}")
        n += 1

    if n == 0:
        print("(0 tramas WebSocket) Revisa: ¿el handshake TLS quedó dentro de la "
              "captura? ¿está declarado el keylog? ¿la sesión ya estaba abierta?",
              file=sys.stderr)


if __name__ == "__main__":
    main()
