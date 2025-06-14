import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Cargar dataset
df = pd.read_csv("dataset_entrenamiento.csv")

# Características y etiquetas
X = df.drop("etiqueta", axis=1)
y = df["etiqueta"]

# División en entrenamiento y prueba
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Modelo
modelo = RandomForestClassifier(n_estimators=100, random_state=42)
modelo.fit(X_train, y_train)

# Evaluación
y_pred = modelo.predict(X_test)
print(classification_report(y_test, y_pred))

# Guardar modelo
joblib.dump(modelo, "modelo_entrenado.pkl")
print("Modelo guardado como modelo_entrenado.pkl")
