
# !/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extracción de fingerprints de tráfico de red (TCP/UDP) desde archivos PCAP.
Guarda hashes Nilsimsa como bit arrays en formato NPZ para uso en ML.
Sin dependencias de Polars/Pandas - solo NumPy + Scapy + Nilsimsa.
"""

import os
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
from nilsimsa import Nilsimsa


# =============================================================================
# FUNCIONES DE CONVERSIÓN DE HASH
# =============================================================================

def hex_to_bitarray(hex_hash: str, length: int = 256) -> np.ndarray:
    """
    Convierte un hash hexadecimal de Nilsimsa a array de bits numpy.

    Args:
        hex_hash: String hexadecimal de 64 caracteres (256 bits)
        length: Longitud esperada del hash (por defecto 256)

    Returns:
        np.ndarray de shape (256,) con valores 0/1 (dtype=np.uint8)
    """
    int_val = int(hex_hash, 16)
    bits = np.array([(int_val >> (length - 1 - i)) & 1 for i in range(length)], dtype=np.uint8)
    return bits


def hex_to_bitarray_fast(hex_hash: str) -> np.ndarray:
    """
    Versión optimizada usando numpy.unpackbits (más rápida para grandes volúmenes).

    Args:
        hex_hash: String hexadecimal de 64 caracteres (256 bits)

    Returns:
        np.ndarray de shape (256,) con valores 0/1 (dtype=np.uint8)
    """
    byte_data = bytes.fromhex(hex_hash)  # 32 bytes = 256 bits
    bits = np.unpackbits(np.frombuffer(byte_data, dtype=np.uint8))
    return bits


def bitarray_to_hex(bit_array: np.ndarray) -> str:
    """
    Convierte array de bits de vuelta a hexadecimal (para verificación/debug).

    Args:
        bit_array: np.ndarray de shape (256,) con valores 0/1

    Returns:
        String hexadecimal de 64 caracteres
    """
    int_val = int(''.join(bit_array.astype(str)), 2)
    return f'{int_val:064x}'


# =============================================================================
# EXTRACCIÓN DE FEATURES DESDE PCAP
# =============================================================================

def extract_fp_tcp_udp_numpy(ruta: str, N_segmento: int = 10, udp_timeout: int = 10) -> list:
    """
    Extrae fingerprints de tráfico TCP/UDP desde un archivo PCAP.

    Args:
        ruta: Path al archivo .pcap o .pcapng
        N_segmento: Número de paquetes por segmento para hashing
        udp_timeout: Timeout en segundos para considerar nueva sesión UDP

    Returns:
        Lista de diccionarios con features y hash como bit array numpy
    """
    paquetes = rdpcap(ruta)
    paquetes = sorted(paquetes, key=lambda p: p.time)

    # Verificar orden temporal
    desorden = any(paquetes[i].time < paquetes[i - 1].time for i in range(1, len(paquetes)))
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

    filas_data = []

    for pkt in paquetes:
        if IP not in pkt:
            continue

        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst

        # ==================== TCP ====================
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            a = sorted([(ip_src, sport), (ip_dst, dport)])
            flujo = (a[0][0], a[0][1], a[1][0], a[1][1], "TCP")
            total_tcp[flujo] += 1

            if flujo not in tiempos_tcp:
                tiempos_tcp[flujo] = None

            # Features TCP
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
            tiempos_tcp[flujo] = pkt.time

            vector = [flags, size, direccion, window, payload, iat]
            buffers_tcp[flujo].extend(vector)
            conteo_tcp[flujo] += 1

            if conteo_tcp[flujo] == N_segmento:
                segmento_id_tcp[flujo] += 1
                hash_fp = Nilsimsa(bytes(buffers_tcp[flujo])).hexdigest()
                bit_array = hex_to_bitarray_fast(hash_fp)  # ← Hash como bit array

                filas_data.append({
                    "proto": 1,  # TCP = 1
                    "src_ip": a[0][0],
                    "src_port": a[0][1],
                    "dst_ip": a[1][0],
                    "dst_port": a[1][1],
                    "segmento": segmento_id_tcp[flujo],
                    "pkts_segmento": N_segmento,
                    "pkts_totales_flujo": total_tcp[flujo],
                    "hash_bits": bit_array  # np.ndarray (256,)
                })
                buffers_tcp[flujo] = []
                conteo_tcp[flujo] = 0

        # ==================== UDP ====================
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            flujo = (ip_src, sport, ip_dst, dport, "UDP")
            total_udp[flujo] += 1

            if flujo not in tiempos_udp:
                tiempos_udp[flujo] = pkt.time

            if pkt.time - tiempos_udp[flujo] > udp_timeout:
                buffers_udp[flujo] = []
                conteo_udp[flujo] = 0
            tiempos_udp[flujo] = pkt.time

            # Features UDP
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
                bit_array = hex_to_bitarray_fast(hash_fp)

                filas_data.append({
                    "proto": 0,  # UDP = 0
                    "src_ip": ip_src,
                    "src_port": sport,
                    "dst_ip": ip_dst,
                    "dst_port": dport,
                    "segmento": segmento_id_udp[flujo],
                    "pkts_segmento": N_segmento,
                    "pkts_totales_flujo": total_udp[flujo],
                    "hash_bits": bit_array  # np.ndarray (256,)
                })
                buffers_udp[flujo] = []
                conteo_udp[flujo] = 0

    return filas_data


# =============================================================================
# GUARDADO Y CARGA DE DATOS EN FORMATO NPZ
# =============================================================================

def guardar_a_npz(filas_data: list, ruta_salida: str):
    """
    Guarda los datos extraídos en formato .npz comprimido para ML.

    Args:
        filas_data: Lista de diccionarios con features y hash_bits
        ruta_salida: Path donde guardar el archivo .npz
    """
    if not filas_data:
        print("[WARN] No hay datos para guardar")
        return

    features_num = []
    hash_bits_list = []
    metadatos = {
        'src_port': [], 'dst_port': [], 'segmento': [],
        'pkts_segmento': [], 'pkts_totales_flujo': [], 'proto': []
    }

    for fila in filas_data:
        # Features numéricas para ML
        features_num.append([
            fila['proto'],
            fila['src_port'],
            fila['dst_port'],
            fila['segmento'],
            fila['pkts_segmento'],
            fila['pkts_totales_flujo']
        ])

        # Hash como bit array (256 dimensiones)
        hash_bits_list.append(fila['hash_bits'])

        # Metadatos numéricos
        for key in metadatos:
            metadatos[key].append(fila[key])

    # Convertir a arrays numpy
    X_features = np.array(features_num, dtype=np.uint16)   # (n_samples, 6)
    X_hash = np.array(hash_bits_list, dtype=np.uint8)       # (n_samples, 256)
    meta_array = np.array([metadatos[k] for k in metadatos], dtype=np.uint16).T

    # Guardar comprimido
    np.savez_compressed(
        ruta_salida,
        features=X_features,
        hash_bits=X_hash,
        metadata=meta_array,
        feature_names=np.array(['proto', 'src_port', 'dst_port', 'segmento', 'pkts_segmento', 'pkts_totales_flujo']),
        hash_description=np.array(['nilsimsa_256bits']),
        allow_pickle=False
    )
    print(f"[OK] Guardado: {ruta_salida} | Samples: {len(filas_data)}")


def cargar_datos_ml(ruta_npz: str):
    """
    Carga datos desde .npz para usar directamente en scikit-learn, PyTorch, etc.

    Args:
        ruta_npz: Path al archivo .npz

    Returns:
        tuple: (X, metadata, raw_data)
            - X: np.ndarray con features listas para ML (hash + features numéricas)
            - metadata: dict con metadatos si existen
            - raw_data: objeto np.load para acceso avanzado
    """
    data = np.load(ruta_npz, allow_pickle=False)

    X_hash = data['hash_bits'].astype(np.float32)           # (n, 256)
    X_features = data['features'].astype(np.float32)        # (n, 6)

    # Concatenar hash + features numéricas (ajustar según necesidad)
    X = np.hstack([X_hash, X_features])  # (n, 262)

    metadata = {
        'names': data['feature_names'],
        'hash_desc': data['hash_description']
    } if 'feature_names' in data else None

    return X, metadata, data


# =============================================================================
# PROCESAMIENTO DE DIRECTORIO COMPLETO
# =============================================================================

def procesar_directorio_pcaps_numpy(carpeta_entrada: str, carpeta_salida: str = None,
                                    N_segmento: int = 10, udp_timeout: int = 10):
    """
    Procesa todos los PCAPs en un directorio y guarda resultados en NPZ.

    Args:
        carpeta_entrada: Directorio con archivos .pcap/.pcapng
        carpeta_salida: Directorio donde guardar archivos .npz (None = solo retorna)
        N_segmento: Paquetes por segmento para hashing
        udp_timeout: Timeout para sesiones UDP

    Returns:
        tuple: (X, metadata, raw) del dataset completo, o None si no hay datos
    """
    if carpeta_salida:
        os.makedirs(carpeta_salida, exist_ok=True)

    all_filas = []

    for root, _, files in os.walk(carpeta_entrada):
        for archivo in files:
            if not archivo.endswith((".pcap", ".pcapng")):
                continue

            ruta = os.path.join(root, archivo)
            print(f" Procesando: {ruta}")

            try:
                filas = extract_fp_tcp_udp_numpy(ruta, N_segmento, udp_timeout)
                all_filas.extend(filas)

                if carpeta_salida and filas:
                    sub = os.path.basename(root)
                    nombre = archivo.replace(".pcap", "").replace(".pcapng", "")
                    salida = os.path.join(carpeta_salida, f"{sub}_{nombre}_fp.npz")
                    guardar_a_npz(filas, salida)

            except Exception as e:
                print(f"[ERROR] {ruta}: {e}")
                continue

    # Guardar dataset consolidado
    if carpeta_salida and all_filas:
        salida_total = os.path.join(carpeta_salida, "dataset_completo.npz")
        guardar_a_npz(all_filas, salida_total)
        print(f" Dataset completo: {salida_total}")
        return cargar_datos_ml(salida_total)

    return None, None, None


if __name__ == "__main__":
    folder_output = "/home/labciber2/Documentos/ConjuntosTesisEdwin/TonIoT"
    procesar_directorio_pcaps_numpy("/home/labciber2/Documentos/ConjuntosTesisEdwin/TonIoT/Ataques_pcap/normal_DDoS", folder_output)
    procesar_directorio_pcaps_numpy("/home/labciber2/Documentos/ConjuntosTesisEdwin/TonIoT/Nomarl_pcaps", folder_output)