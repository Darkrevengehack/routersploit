
# Mobile UI Optimization for RouterSploit
# Mejora la visualización y usabilidad en pantallas pequeñas

from routersploit.core.exploit.printer import (
    print_info, print_status, print_success, print_error, print_table, print_empty
)
import shutil
import os

# Guardar funciones originales
original_print_table = print_table
original_print_info = print_info
original_print_status = print_status
original_print_success = print_success
original_print_error = print_error

# Función para obtener ancho de terminal
def get_terminal_width():
    try:
        return shutil.get_terminal_size().columns
    except:
        return 80  # Valor por defecto

# Versión optimizada de print_table para pantallas pequeñas
def mobile_print_table(headers, *args, **kwargs):
    terminal_width = get_terminal_width()
    
    # Para pantallas muy estrechas
    if terminal_width < 50:
        # Mostrar tabla en formato vertical para mejor visualización
        data = kwargs.get('data', None)
        if data and len(data) > 0:
            # Imprimir cada fila como un grupo de datos
            for i, row in enumerate(data):
                print_empty(f"--- Item {i+1} ---")
                for j, header in enumerate(headers):
                    if j < len(row):
                        print_empty(f"{header}: {row[j]}")
                print_empty()
            return
    
    # Para pantallas estrechas pero no tanto
    if terminal_width < 80:
        # Abreviar cabeceras largas
        short_headers = []
        for header in headers:
            if isinstance(header, str) and len(header) > 10:
                short_header = header[:7] + "..."
                short_headers.append(short_header)
            else:
                short_headers.append(header)
        
        # Usar cabeceras abreviadas
        return original_print_table(short_headers, *args, **kwargs)
    
    # Para pantallas normales, usar función original
    return original_print_table(headers, *args, **kwargs)

# Versiones optimizadas de las funciones de impresión
def mobile_print_info(*args, **kwargs):
    terminal_width = get_terminal_width()
    
    # Para pantallas estrechas, agregar saltos de línea si es necesario
    if terminal_width < 60 and len(args) > 0 and len(str(args[0])) > terminal_width - 10:
        # Dividir texto largo en múltiples líneas
        text = str(args[0])
        chunks = [text[i:i+terminal_width-10] for i in range(0, len(text), terminal_width-10)]
        
        for chunk in chunks:
            original_print_info(chunk, *args[1:], **kwargs)
        return
    
    return original_print_info(*args, **kwargs)

def mobile_print_status(*args, **kwargs):
    terminal_width = get_terminal_width()
    
    if terminal_width < 60 and len(args) > 0 and len(str(args[0])) > terminal_width - 10:
        text = str(args[0])
        chunks = [text[i:i+terminal_width-10] for i in range(0, len(text), terminal_width-10)]
        
        for chunk in chunks:
            original_print_status(chunk, *args[1:], **kwargs)
        return
    
    return original_print_status(*args, **kwargs)

def mobile_print_success(*args, **kwargs):
    terminal_width = get_terminal_width()
    
    if terminal_width < 60 and len(args) > 0 and len(str(args[0])) > terminal_width - 10:
        text = str(args[0])
        chunks = [text[i:i+terminal_width-10] for i in range(0, len(text), terminal_width-10)]
        
        for chunk in chunks:
            original_print_success(chunk, *args[1:], **kwargs)
        return
    
    return original_print_success(*args, **kwargs)

def mobile_print_error(*args, **kwargs):
    terminal_width = get_terminal_width()
    
    if terminal_width < 60 and len(args) > 0 and len(str(args[0])) > terminal_width - 10:
        text = str(args[0])
        chunks = [text[i:i+terminal_width-10] for i in range(0, len(text), terminal_width-10)]
        
        for chunk in chunks:
            original_print_error(chunk, *args[1:], **kwargs)
        return
    
    return original_print_error(*args, **kwargs)

# Reemplazar las funciones originales con las versiones optimizadas
print_table = mobile_print_table
print_info = mobile_print_info
print_status = mobile_print_status
print_success = mobile_print_success
print_error = mobile_print_error

# Notificar que el parche se ha cargado
if os.environ.get("RSF_VERBOSE", "0") == "1":
    original_print_info("Mobile UI optimization loaded")
