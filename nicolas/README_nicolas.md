# Parte de Nicolás — Servicio de Cuentas + Captura

Resultados a mi cargo: **R1 anuncio**, **R2 login (token)**, **R3 saldo**, **R7 dev/debug: transferencia + validación de origen**.

## Datos del laboratorio
- **Panel web:** https://alpespay.datoid.co/
- **Protocolo (WebSocket/TLS):** `wss://alpespay.datoid.co:9010/`
- **Interfaz de captura:** `en0` (192.168.1.4). El lab es **remoto**, NO uses `lo0`.
- **Usuario y PIN:** en `nicolas/credenciales.local.md` (fuera del repo, por ética).

> ⚠️ Ética (código del enunciado): NO compartir credenciales/tokens con otros
> equipos ni subirlas al repo. `.gitignore` ya excluye `*.local.md`, `*.pcap` y el keylog.

## Antes de empezar (bloqueadores)
- [x] `ws_cliente.py` — implementado en la raíz del proyecto (WebSocket/TLS + keylog).
- [ ] Instalar Wireshark, Chrome y un Python con OpenSSL 1.1.1+ (tu Python de sistema es LibreSSL 2.8.3 → no sirve para capturar; usa el de Homebrew).

## Flujo de trabajo
1. **Capturar** (usa la banca: login con las credenciales del archivo local, ver saldo, una transferencia):
   ```bash
   tools/capturar-mac.sh                 # ya apunta a https://alpespay.datoid.co/
   # si tu interfaz no es en0:  IFACE=en1 tools/capturar-mac.sh
   ```
2. **Extraer tramas** para deducir el protocolo:
   ```bash
   /opt/homebrew/bin/python3 nicolas/extraer_frames.py /tmp/alpes_captura.pcap
   ```
3. **Rellenar constantes** en `cliente_cuentas.py` (todo lo marcado `# <-- CONFIRMAR EN CAPTURA`):
   servicio de cuentas, op_ids (anuncio/login/saldo/transferir), anchos de la cabecera,
   y el formato del contenido de login/saldo/transferencia.
4. **Ejecutar y guardar tokens** (usa el Python con OpenSSL para poder importar ws_cliente):
   ```bash
   P=/opt/homebrew/bin/python3
   $P nicolas/cliente_cuentas.py wss://alpespay.datoid.co:9010/ anuncio
   $P nicolas/cliente_cuentas.py wss://alpespay.datoid.co:9010/ login --usuario <USUARIO> --pin <PIN>
   $P nicolas/cliente_cuentas.py wss://alpespay.datoid.co:9010/ saldo --token <hex>
   # R7 (dev/debug, con TU token; observa si el servidor valida el origen):
   $P nicolas/cliente_cuentas.py wss://alpespay.datoid.co:9010/ test-origen --token <hex> --origen <cuenta_no_propia> --destino <cuenta_propia> --centavos 1
   ```

## R7 — sobre la duda del profesor
La "validación del origen frente al titular del token" **se prueba contra el servidor**:
se envía la transferencia indicando un **origen distinto al propio** pero usando **mi
propio token**, y se observa si el servidor **rechaza o acepta**. El resultado del reto
es ese comportamiento observado. **No** se usan credenciales ni la cuenta de otro equipo:
el profesor confirmó que el límite de alcance prohíbe atacar/adivinar/usar credenciales
ajenas, no probar cómo responde el servidor con lo mío.

## Registro de sesión (pegar aquí los tokens)
| Resultado | Token del servidor | Notas |
|---|---|---|
| R1 anuncio | | |
| R2 login | | |
| R3 saldo | | |
| R7 origen | | ¿aceptó/rechazó el origen ajeno? |
