#!/usr/bin/env python3

import logging.handlers
import sys
if sys.version_info.major < 3:
    print("RouterSploit supports only Python3. Rerun application in Python3 environment.")
    exit(0)

import os

def is_running_in_termux():
    """Detecta si RouterSploit está ejecutándose en Termux usando múltiples métodos"""
    # Método 1: Verificar PREFIX en variables de entorno
    if "com.termux" in os.environ.get("PREFIX", ""):
        return True
    
    # Método 2: Verificar la existencia de rutas específicas de Termux
    if os.path.exists("/data/data/com.termux/"):
        return True
    
    # Método 3: Verificar si estamos en Android
    try:
        with open("/proc/version", "r") as f:
            if "android" in f.read().lower():
                return True
    except:
        pass
    
    return False

# Añadir soporte para Termux sin root
if is_running_in_termux():
    print("RouterSploit en Termux - Aplicando mejoras de compatibilidad...")
    
    # Asegurarse de que el directorio de parches esté en el path
    patches_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patches")
    if patches_dir not in sys.path:
        sys.path.append(patches_dir)
    
    # Cargar los parches con manejo de excepciones mejorado
    try:
        # Intentar cargar el parche de Termux
        import termux_patch
        print("✓ Parche de Termux aplicado correctamente")
    except ImportError:
        print("✗ Error: No se encontró el módulo termux_patch")
        print("  Solución: Verifica que el archivo termux_patch.py está en el directorio patches/")
    except AttributeError as e:
        print(f"✗ Error en el parche de Termux: {str(e)}")
        print("  Solución: Revisa la implementación del parche termux_patch.py")
    
    try:
        # Intentar cargar el parche de interfaz móvil
        import mobile_ui_patch
        print("✓ Parche de interfaz móvil aplicado correctamente")
    except ImportError:
        print("✗ Error: No se encontró el módulo mobile_ui_patch")
        print("  Solución: Verifica que el archivo mobile_ui_patch.py está en el directorio patches/")
    except Exception as e:
        print(f"✗ Error en el parche de interfaz móvil: {str(e)}")
        print("  Solución: Revisa la implementación del parche mobile_ui_patch.py")

from routersploit.interpreter import RoutersploitInterpreter

log_handler = logging.handlers.RotatingFileHandler(filename="routersploit.log", maxBytes=500000)
log_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s       %(message)s")
log_handler.setFormatter(log_formatter)
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(log_handler)


def routersploit(argv):
    rsf = RoutersploitInterpreter()
    if len(argv[1:]):
        rsf.nonInteractive(argv)
    else:
        rsf.start()

if __name__ == "__main__":
    try:
        routersploit(sys.argv)
    except (KeyboardInterrupt, SystemExit):
        pass
