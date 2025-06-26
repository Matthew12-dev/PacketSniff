import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# 1. Cargar el dataset y conservar solo las columnas útiles
columnas_utiles = [
    'Destination Port', 'Fwd Packet Length Max', 'Fwd Packet Length Min',
    'Fwd Packet Length Mean', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Packet Length Mean',
    'Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Label'
]
df = pd.read_csv('datosML.csv')
df = df[columnas_utiles]

# 2. Separar en características (X) y etiqueta (y)
X = df.drop('Label', axis=1)
y = df['Label']

# 3. Limpiar datos: reemplazar infinitos por NaN y luego rellenar con la media
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(X.mean(), inplace=True)

# 4. División en entrenamiento y prueba
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 5. Crear y entrenar modelo con balanceo de clases
clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
clf.fit(X_train, y_train)

# 6. Evaluar modelo
y_pred = clf.predict(X_test)
print("=== Matriz de Confusión ===")
print(confusion_matrix(y_test, y_pred))

print("\n=== Reporte de Clasificación ===")
print(classification_report(y_test, y_pred))

print("\n=== Precisión ===")
print(f"{accuracy_score(y_test, y_pred) * 100:.2f}%")

# 7. Guardar modelo junto con las columnas utilizadas
joblib.dump((clf, X.columns.tolist()), 'modelo_randomforest.pkl')
print("\nModelo guardado como 'modelo_randomforest.pkl'")