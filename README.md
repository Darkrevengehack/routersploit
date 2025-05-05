# RouterSploit

Version 3.5.0

Framework de explotación para dispositivos embebidos, con mejoras específicas para uso en Termux.

## Características añadidas

- Soporte mejorado para Termux sin root
- Interfaz optimizada para pantallas móviles
- Sistema de actualización automática de CVEs
- Soporte para protocolos modernos (TLS/SSL)
- Sistema de plugins extensible

## Instalación

```bash
git clone https://github.com/Darkrevengehack/routersploit.git
cd routersploit
python3 -m pip install -r requirements.txt
python3 rsf.py
## ¿Por qué usar entornos virtuales en Termux?

Los entornos virtuales (venv) ofrecen varias ventajas importantes al trabajar con RouterSploit en Termux:

1. **Aislamiento de dependencias**: Evita conflictos con otros paquetes Python instalados en Termux
2. **Fácil gestión de versiones**: Asegura que estás usando las versiones correctas de cada biblioteca
3. **Mejor rendimiento**: Reduce la sobrecarga de memoria al cargar solo las bibliotecas necesarias
4. **Fácil limpieza**: Puedes eliminar el entorno virtual sin afectar al resto del sistema
5. **Portabilidad**: Puedes mover o compartir el entorno completo entre dispositivos

Para activar el entorno después de cerrar la terminal, usa siempre:
```bash
cd routersploit
source venv/bin/activate.fish
```

## Uso

### Comandos principales

- `help` - Muestra la ayuda
- `use <módulo>` - Selecciona un módulo
- `show options` - Muestra opciones del módulo
- `set <opción> <valor>` - Establece valor para una opción
- `run` - Ejecuta el módulo
- `update_cves` - Busca y genera plantillas para CVEs recientes
- `plugin create <nombre>` - Crea un nuevo plugin
- `touch_menu` - Muestra un menú optimizado para pantallas táctiles

## Mejoras Implementadas

### 1. Soporte Mejorado para Termux
- Detección automática de entorno Termux
- Adaptaciones para interfaces de pantallas pequeñas
- Manejo optimizado de recursos limitados

### 2. Interfaz para Dispositivos Móviles
- Menú táctil optimizado para pantallas pequeñas
- Formato adaptativo para tablas y salidas largas
- Detección automática del tamaño de pantalla

### 3. Sistema de Actualización Automática de CVEs
- Búsqueda automática de vulnerabilidades recientes en la NVD
- Generación de plantillas para exploits basadas en CVEs
- Clasificación inteligente por tipo de vulnerabilidad
- Integración con API oficial con gestión de claves

### 4. Soporte para Protocolos Modernos
- Escáner TLS/SSL para detectar configuraciones inseguras
- Detección de vulnerabilidades como Heartbleed, ROBOT, y CCS Injection
- Soporte para protocolos IoT como MQTT
- Análisis de certificados SSL

### 5. Sistema de Plugins
- Arquitectura extensible para plugins de terceros
- Carga dinámica de funcionalidades adicionales
- Sistema de registro de plugins en el intérprete

### 6. Otras Mejoras
- Mejor manejo de errores y reintentos
- Configuración más robusta
- Documentación mejorada

## API Key para búsqueda de CVEs

Para usar la funcionalidad de búsqueda de CVEs con mejor rendimiento:

1. Obtén una API key gratuita en: https://nvd.nist.gov/developers/request-an-api-key
2. Al ejecutar el comando `update_cves` por primera vez, se te pedirá si deseas configurar una API key
3. También puedes configurar manualmente la API key creando un archivo `config.ini` en `routersploit/utils/updaters/` basado en el archivo `config.ini.example`

## Permisos de ejecución

Después de clonar el repositorio, es necesario otorgar permisos de ejecución a ciertos archivos:

```bash
# Hacer ejecutable el actualizador de CVEs
chmod +x routersploit/utils/updaters/cve_updater.py

# El script principal ya debería tener permisos de ejecución
chmod +x rsf.py
```

Si creas tus propios plugins, también necesitarás darles permisos de ejecución:
```bash
chmod +x routersploit/plugins/mi_plugin/__init__.py
```

## Creación de plugins personalizados

Puedes extender RouterSploit con plugins personalizados:

1. Crea un nuevo plugin usando el comando: `plugin create nombre_plugin`
2. Edita el archivo `plugins/nombre_plugin/__init__.py` para implementar tu funcionalidad
3. Reinicia RouterSploit para cargar automáticamente tu plugin

## Licencia

Este proyecto es una modificación de RouterSploit y mantiene la licencia original.

## Contribuir

Si encuentras algún problema o tienes ideas para mejorar esta versión de RouterSploit, por favor abre un issue o envía un pull request.
```
