import os
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
from nilsimsa import Nilsimsa
import pandas as pd


# Función principal para extraer TCP y UDP
def extract_fp_tcp_udp(ruta, N_segmento=10, udp_timeout=10):

    paquetes = rdpcap(ruta)
    paquetes = sorted(paquetes, key=lambda p: p.time)
    # Verificar si el archivo estaba desordenado
    desorden = False
    for i in range(1, len(paquetes)):
        if paquetes[i].time < paquetes[i - 1].time:
            desorden = True
            break

    if desorden:
        print(f"[INFO] {ruta} tenía paquetes fuera de orden y fueron corregidos.")

    # Estado TCP
    buffers_tcp = defaultdict(list)
    conteo_tcp = defaultdict(int)
    total_tcp = defaultdict(int)
    tiempos_tcp = {}
    segmento_id_tcp = defaultdict(int)

    # Estado UDP
    buffers_udp = defaultdict(list)
    conteo_udp = defaultdict(int)
    total_udp = defaultdict(int)
    tiempos_udp = {}
    prev_iat_udp = {}
    segmento_id_udp = defaultdict(int)

    filas = []

    for pkt in paquetes:

        if IP not in pkt:
            continue

        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst

        # TCP
        if TCP in pkt:

            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            a = sorted([(ip_src, sport), (ip_dst, dport)])
            flujo = (a[0][0], a[0][1], a[1][0], a[1][1], "TCP")

            total_tcp[flujo] += 1

            if flujo not in tiempos_tcp:
                tiempos_tcp[flujo] = None

            # Features
            flags = int(pkt[TCP].flags)
            size = len(pkt) & 0xff
            direccion = 0 if pkt[IP].src == a[0][0] else 1
            window = min(pkt[TCP].window // 256, 255)
            payload = min(len(pkt[TCP].payload) // 16, 255)

            prev = tiempos_tcp[flujo]
            if prev is None:
                iat = 0
            else:
                delta = max(0, int((pkt.time - prev) * 1000))
                iat = min(delta // 10, 255)
            print("IAT:", iat)

            tiempos_tcp[flujo] = pkt.time

            vector = [flags, size, direccion, window, payload, iat]

            buffers_tcp[flujo].extend(vector)
            conteo_tcp[flujo] += 1

            if conteo_tcp[flujo] == N_segmento:

                segmento_id_tcp[flujo] += 1

                hash_fp = Nilsimsa(bytes(buffers_tcp[flujo])).hexdigest()

                filas.append({
                    "proto": "TCP",
                    "src_ip": a[0][0],
                    "src_port": a[0][1],
                    "dst_ip": a[1][0],
                    "dst_port": a[1][1],
                    "segmento": segmento_id_tcp[flujo],
                    "pkts_segmento": N_segmento,
                    "pkts_totales_flujo": total_tcp[flujo],
                    "hash": hash_fp
                })

                buffers_tcp[flujo] = []
                conteo_tcp[flujo] = 0


        # Para paquetes UDP
        elif UDP in pkt:

            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

            flujo = (ip_src, sport, ip_dst, dport, "UDP")

            total_udp[flujo] += 1

            # timeout para definir sesión
            if flujo not in tiempos_udp:
                tiempos_udp[flujo] = pkt.time

            if pkt.time - tiempos_udp[flujo] > udp_timeout:
                buffers_udp[flujo] = []
                conteo_udp[flujo] = 0

            tiempos_udp[flujo] = pkt.time

            #  Features UDP
            payload = min(len(pkt[UDP].payload) // 16, 255)
            size = len(pkt) & 0xff

            prev = prev_iat_udp.get(flujo)
            if prev is None:
                iat = 0
            else:
                delta = max(0, int((pkt.time - prev) * 1000))
                iat = min(delta // 10, 255)

            prev_iat_udp[flujo] = pkt.time

            vector = [payload, size, iat]

            buffers_udp[flujo].extend(vector)
            conteo_udp[flujo] += 1

            if conteo_udp[flujo] == N_segmento:

                segmento_id_udp[flujo] += 1

                hash_fp = Nilsimsa(bytes(buffers_udp[flujo])).hexdigest()

                filas.append({
                    "proto": "UDP",
                    "src_ip": ip_src,
                    "src_port": sport,
                    "dst_ip": ip_dst,
                    "dst_port": dport,
                    "segmento": segmento_id_udp[flujo],
                    "pkts_segmento": N_segmento,
                    "pkts_totales_flujo": total_udp[flujo],
                    "hash": hash_fp
                })

                buffers_udp[flujo] = []
                conteo_udp[flujo] = 0

    return pd.DataFrame(filas)


# Con esta función se procesa un flujo completo
def procesar_directorio_pcaps(carpeta_entrada, carpeta_salida):

    os.makedirs(carpeta_salida, exist_ok=True)

    for root, _, files in os.walk(carpeta_entrada):

        for archivo in files:

            if not archivo.endswith((".pcap", ".pcapng")):
                continue

            ruta = os.path.join(root, archivo)
            print("Procesando:", ruta)

            df = extract_fp_tcp_udp(ruta)

            sub = os.path.basename(root)
            nombre = archivo.replace(".pcap", "").replace(".pcapng", "")

            salida = os.path.join(
                carpeta_salida,
                f"{sub}_{nombre}_fp.csv"
            )

            df.to_csv(salida, index=False)

            print("Guardado:", salida)


df = procesar_directorio_pcaps("/media/edwin/59941973-d0c9-4790-8304-ab071c865050/edwin/MaestríaINAOE/"
                               "IoT_Sentinel-master/captures_IoT_Sentinel/captures_IoT-Sentinel/D-LinkSwitch/",
                               "/media/edwin/59941973-d0c9-4790-8304-ab071c865050/edwin/MaestríaINAOE/"
                               "IoT_Sentinel-master/captures_IoT_Sentinel/captures_IoT-Sentinel/D-LinkSwitch/"
                               "fingerprints_tcp_udp.csv")
