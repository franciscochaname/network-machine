# 🌐 Guía de Configuración y Despliegue — NOC Engine v4.0

Esta guía explica los pasos necesarios para hacer funcionar este sistema en una nueva máquina, ya sea descargando el código desde GitHub o copiándolo manualmente.

## 📋 Requisitos Previos

1.  **Python 3.10 o superior**: El sistema requiere una versión moderna de Python. Puedes descargarlo en [python.org](https://www.python.org/).
2.  **Git (Opcional)**: Para clonar el repositorio si usas GitHub.

---

## 🚀 Pasos para la Instalación

### 1. Obtener el Código
Si descargas el código en bruto, descomprímelo en una carpeta. Si usas Git, ejecuta:
```bash
git clone <url-del-repositorio>
cd "network machine"
```

### 2. Crear un Entorno Virtual (Recomendado)
Es altamente recomendable usar un entorno virtual para no interferir con otras instalaciones de Python.

**En Windows:**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**En Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalar Dependencias
Una vez activado el entorno virtual, instala las librerías necesarias:
```bash
pip install -r requirements.txt
```

### 4. Configuración de Variables de Entorno (`.env`)
El sistema utiliza un archivo `.env` para manejar configuraciones sensibles (como contraseñas y claves de API). 
Debes crear un archivo llamado `.env` en la raíz del proyecto con el siguiente contenido (puedes copiar el ejemplo si existe un `.env.example`):

```env
# Configuración del Administrador Inicial
ADMIN_USER=admin
ADMIN_PASS=tu_contraseña_segura

# Configuración de Base de Datos
DATABASE_URL=sqlite:///database/sistema.db

# Otras configuraciones (MicroTik, etc)
# ...
```

### 5. Inicializar la Base de Datos
Antes de arrancar la aplicación por primera vez, debes crear la base de datos y el usuario administrador inicial ejecutando el script de reconstrucción:
```bash
python reset_db.py
```
*Nota: Esto borrará la base de datos actual y creará una nueva basada en los modelos y los valores definidos en tu `.env`.*

---

## 🖥️ Cómo Ejecutar la Aplicación

Para iniciar el panel de control (NOC Dashboard), utiliza **Streamlit**:

```bash
streamlit run app.py
```

El sistema se abrirá automáticamente en tu navegador (usualmente en `http://localhost:8501`).

---

## 🛠️ Solución de Problemas Comunes

- **Error: "ModuleNotFoundError"**: Asegúrate de que el entorno virtual esté **activo** y de haber ejecutado `pip install -r requirements.txt`.
- **Base de Datos bloqueada**: Cierra cualquier proceso de Python que esté usando `sistema.db` y reintenta.
- **Error de Conexión Mikrotik**: Verifica que el router tenga habilitado el acceso por API (puerto 8728) o API-SSL (puerto 8729) y que las credenciales en el dashboard sean correctas.

---
*Desarrollado para la gestión avanzada de infraestructuras de red.*
