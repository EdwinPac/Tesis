import numpy as np

def get_hashes(file: str) -> np.ndarray:
    data = np.load(file, allow_pickle=False)
    return data['hash_bits'].astype(np.float32)


def get_normal_traffic():
    carpeta_entrada = "/home/labciber2/Documentos/ConjuntosTesisEdwin/TonIoT/nombre.npz"
    X = get_hashes(carpeta_entrada)      # (n, 256)
    y = np.ones(len(X), dtype=np.int8)       # 1 = Normal
    return X, y


def get_anomaly_traffic():
    carpeta_entrada = "/home/labciber2/Documentos/ConjuntosTesisEdwin/TonIoT/nombre.npz"
    X = get_hashes(carpeta_entrada)      # (n, 256)
    y = np.zeros(len(X), dtype=np.int8)      # 0 = Anomalía
    return X, y