from sklearn import svm
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from load_data import get_normal_traffic, get_anomaly_traffic
import numpy as np

# 1. Carga de datos
normal_traffic_X, normal_traffic_y = get_normal_traffic()
anomaly_traffic_X, anomaly_traffic_y = get_anomaly_traffic()

# 2. División Train/Test (Separada por clase inicialmente)
normal_traffic_X_train, normal_traffic_X_test, normal_traffic_y_train, normal_traffic_y_test = train_test_split(
    normal_traffic_X, normal_traffic_y, test_size=0.3, random_state=42)

anomaly_traffic_X_train, anomaly_traffic_X_test, anomaly_traffic_y_train, anomaly_traffic_y_test = train_test_split(
    anomaly_traffic_X, anomaly_traffic_y, test_size=0.3, random_state=42)

# 3. Combinación de datos para entrenamiento
X_train = np.vstack([normal_traffic_X_train, anomaly_traffic_X_train])
y_train = np.hstack([normal_traffic_y_train, anomaly_traffic_y_train])

# 4. Combinación de datos para prueba
X_test = np.vstack([normal_traffic_X_test, anomaly_traffic_X_test])
y_test = np.hstack([normal_traffic_y_test, anomaly_traffic_y_test])

# --- VALIDACIÓN CRUZADA ---
print("Iniciando Validación Cruzada (5-Folds Estratificados)...")

# Configuramos K-Folds estratificados para mantener el balance de clases en cada fold
kfold = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

# Creamos el modelo (sin entrenar aún)
clf = svm.SVC()

# Ejecutamos validación cruzada en el conjunto de ENTRENAMIENTO
# Usamos 'f1_weighted' porque es mejor para datasets desbalanceados que 'accuracy'
scores = cross_val_score(clf, X_train, y_train, cv=kfold, scoring='f1_weighted')

print(f"Puntuaciones F1 por fold: {scores}")
print(f"Media F1: {scores.mean():.4f} (+/- {scores.std() * 2:.4f})")
print("-" * 30)

# 5. Entrenamiento final con todos los datos de entrenamiento
clf.fit(X_train, y_train)

# 6. Hacer predicciones en el conjunto de HOLD-OUT (Test)
y_pred = clf.predict(X_test)

# 7. Generar classification report final
print("Reporte de Clasificación (Conjunto de Test):")
print(classification_report(y_test, y_pred))