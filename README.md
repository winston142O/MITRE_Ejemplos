# Configuración Inicial

## 1. Crear un entorno virtual de python

```python -m venv <nombre_entorno>```

## 2. Activar entorno e instalar dependencias

### Activar entorno

#### Windows

```./<entorno>/Scripts/activate```

#### Linux

```source <entorno>/bin/activate```

### Instalar dependencias

```python -m pip install -r requirements.txt```

## 3. Asignar variables de entorno

Se requiere crear un archivo llamado `api-keys.env` y declarar las siguientes variables:

* OPENAI_API_KEY
* VIRUSTOTAL_API_KEY
