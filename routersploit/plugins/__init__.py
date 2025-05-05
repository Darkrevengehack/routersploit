"""
RouterSploit Plugins
====================

Sistema de plugins para extender RouterSploit con módulos externos.

Cómo usar plugins:
1. Coloca tus plugins en la carpeta plugins/
2. Cada plugin debe ser un directorio con un archivo __init__.py
3. El archivo __init__.py debe contener una función register(interpreter)
"""

import os
import sys
import importlib
import importlib.util
from routersploit.core.exploit.printer import print_info, print_error, print_success, print_status

def load_plugins(interpreter):
    """Carga todos los plugins disponibles"""
    plugins_path = os.path.dirname(os.path.abspath(__file__))
    plugins_dirs = []
    
    # Buscar directorios que podrían ser plugins
    for item in os.listdir(plugins_path):
        item_path = os.path.join(plugins_path, item)
        if os.path.isdir(item_path) and not item.startswith("__"):
            # Verificar si tiene un archivo __init__.py
            init_file = os.path.join(item_path, "__init__.py")
            if os.path.isfile(init_file):
                plugins_dirs.append(item)
    
    # Cargar cada plugin
    loaded_plugins = []
    failed_plugins = []
    
    for plugin_dir in plugins_dirs:
        try:
            # Construir ruta de importación
            import_path = f"routersploit.plugins.{plugin_dir}"
            
            # Importar el plugin
            plugin = importlib.import_module(import_path)
            
            # Verificar si el plugin tiene una función register
            if hasattr(plugin, "register") and callable(plugin.register):
                # Registrar el plugin
                plugin.register(interpreter)
                loaded_plugins.append(plugin_dir)
                print_success(f"Plugin '{plugin_dir}' cargado correctamente")
            else:
                print_error(f"Plugin '{plugin_dir}' no tiene una función register()")
                failed_plugins.append(plugin_dir)
        
        except Exception as e:
            print_error(f"Error al cargar plugin '{plugin_dir}': {str(e)}")
            failed_plugins.append(plugin_dir)
    
    if loaded_plugins:
        print_status(f"Plugins cargados ({len(loaded_plugins)}): {', '.join(loaded_plugins)}")
    
    if failed_plugins:
        print_error(f"Plugins con errores ({len(failed_plugins)}): {', '.join(failed_plugins)}")
    
    return loaded_plugins

def create_plugin_template(name):
    """Crea una plantilla para un nuevo plugin"""
    plugins_path = os.path.dirname(os.path.abspath(__file__))
    plugin_dir = os.path.join(plugins_path, name)
    
    # Verificar si ya existe
    if os.path.exists(plugin_dir):
        print_error(f"El plugin '{name}' ya existe")
        return False
    
    try:
        # Crear directorio del plugin
        os.makedirs(plugin_dir)
        
        # Crear archivo __init__.py
        init_file = os.path.join(plugin_dir, "__init__.py")
        
        with open(init_file, "w") as f:
            f.write('''"""
Plugin: {name}
===========

Descripción de tu plugin aquí.
"""

__author__ = "Tu nombre"
__version__ = "0.1"

from routersploit.core.exploit.printer import print_info, print_success

def register(interpreter):
    """
    Función requerida para registrar el plugin con RouterSploit.
    Recibe el intérprete como parámetro.
    """
    print_success("Plugin {name} v" + __version__ + " cargado correctamente")
    
    # Ejemplo: Agregar un nuevo comando al intérprete
    # interpreter.commands["mi_comando"] = {{
    #     "description": "Descripción de mi comando",
    #     "main_command": True,
    #     "run": 'run_mi_comando',
    #     "complete": None,
    # }}
    #
    # # Agregar el método al intérprete
    # setattr(interpreter.__class__, "run_mi_comando", run_mi_comando)

def run_mi_comando(self, argv):
    """Ejemplo de implementación de un comando personalizado"""
    print_info("¡Comando personalizado ejecutado!")
    return
'''.format(name=name))
        
        # Crear archivo README.md
        readme_file = os.path.join(plugin_dir, "README.md")
        
        with open(readme_file, "w") as f:
            f.write('''# Plugin: {name}

## Descripción
Descripción detallada de tu plugin aquí.

## Características
- Característica 1
- Característica 2

## Instalación
Este plugin se instala automáticamente al colocarlo en la carpeta `plugins/` de RouterSploit.

## Uso
Describe cómo usar tu plugin aquí.

## Autor
Tu nombre

## Versión
0.1
'''.format(name=name))
        
        print_success(f"Plugin '{name}' creado en {plugin_dir}")
        print_info(f"Edita los archivos en {plugin_dir} para implementar tu plugin")
        
        return True
    
    except Exception as e:
        print_error(f"Error al crear plugin: {str(e)}")
        return False
