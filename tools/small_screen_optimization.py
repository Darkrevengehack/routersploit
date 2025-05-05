#!/usr/bin/env python3
# Optimización para pantallas pequeñas en RouterSploit
# Este script añade soporte específico para mejorar la visualización en pantallas pequeñas

import os
import sys
import re
import shutil

# Detectar ruta base de RouterSploit
base_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
printer_path = os.path.join(base_dir, "routersploit", "core", "exploit", "printer.py")

def backup_file(file_path):
    """Crea una copia de seguridad del archivo"""
    backup_path = file_path + ".bak"
    if not os.path.exists(backup_path):
        shutil.copy2(file_path, backup_path)
        print(f"[+] Backup creado: {backup_path}")
    return backup_path

def patch_printer_module():
    """Modifica el módulo printer.py para optimizar la visualización en pantallas pequeñas"""
    if not os.path.exists(printer_path):
        print(f"[-] Error: No se encontró el archivo {printer_path}")
        return False
    
    # Crear backup antes de modificar
    backup_file(printer_path)
    
    # Leer contenido actual
    with open(printer_path, "r") as f:
        content = f.read()
    
    # Verificar si ya está parcheado
    if "get_terminal_width" in content:
        print("[*] El módulo printer.py ya parece estar parcheado")
        response = input("¿Desea forzar el parche de todos modos? (y/n): ")
        if response.lower() != "y":
            return False
    
    # Buscar la función print_table para modificarla
    print_table_pattern = r"def print_table\([^)]*\):[^\n]*\n((?:    .*\n)+)"
    print_table_match = re.search(print_table_pattern, content)
    
    if not print_table_match:
        print("[-] Error: No se pudo encontrar la función print_table")
        return False
    
    print_table_code = print_table_match.group(0)
    
    # Crear versión optimizada de print_table
    optimized_print_table = """def get_terminal_width():
    """Obtiene el ancho de la terminal actual"""
    try:
        return shutil.get_terminal_size().columns
    except:
        return 80  # Valor por defecto

def print_table(headers, *args, **kwargs):
    """Imprime tabla con soporte para pantallas pequeñas"""
    extra_fill = kwargs.get("extra_fill", 5)
    header_separator = kwargs.get("header_separator", "-")
    data = kwargs.get("data", args)
    
    terminal_width = get_terminal_width()
    small_screen = terminal_width < 80
    
    if not data:
        print()
        return
    
    # Ajustar para pantallas pequeñas
    if small_screen:
        # Para pantallas muy estrechas, usar formato vertical
        if terminal_width < 50:
            print_vertical_table(headers, data)
            return
            
        # Para pantallas estrechas pero no tanto, abreviar headers
        headers = [h[:7] + "..." if len(str(h)) > 10 else h for h in headers]
    
    # El resto de la función print_table original
    fill = []
    
    headers = [Color.BOLD + header + Color.END if header != "" else "" for header in headers]
    
    for header in headers:
        length = len(remove_colors(header))
        for dat in data:
            i = headers.index(header)
            if dat and i < len(dat):
                length = max(len(remove_colors(str(dat[i]))), length)
                
        fill.append(length + extra_fill)
    
    for i, prefix in enumerate(headers):
        fill[headers.index(prefix)] = max(len(remove_colors(prefix)) + extra_fill, fill[headers.index(prefix)])
    
    if header_separator:
        print(header_separator.join("{}{}".format(prefix, " " * (fill[headers.index(prefix)] - len(remove_colors(prefix)))) for prefix in headers))
        print(header_separator.join("{}{}".format(header_separator * len(remove_colors(prefix)), header_separator * (fill[headers.index(prefix)] - len(remove_colors(prefix)))) for prefix in headers))
    else:
        print(" ".join("{}{}".format(prefix, " " * (fill[headers.index(prefix)] - len(remove_colors(prefix)))) for prefix in headers))
        print(" ".join("{}{}".format("-" * len(remove_colors(prefix)), " " * (fill[headers.index(prefix)] - len(remove_colors(prefix)))) for prefix in headers))
        
    for dat in data:
        print(" ".join("{}{}".format(dat[headers.index(prefix)] if dat and headers.index(prefix) < len(dat) else "", " " * (fill[headers.index(prefix)] - len(remove_colors(str(dat[headers.index(prefix)]))) if dat and headers.index(prefix) < len(dat) else 0)) for prefix in headers))
    
    print()
    
def print_vertical_table(headers, data):
    """Imprime tabla en formato vertical para pantallas muy pequeñas"""
    if not data:
        print()
        return
    
    for i, row in enumerate(data):
        print()
        print(Color.BOLD + f" --- Item {i+1} --- " + Color.END)
        print()
        
        for j, header in enumerate(headers):
            if j < len(row):
                header_text = remove_colors(header)
                value = row[j]
                print(f"{header_text}: {value}")
        
    print()
"""
    
    # Reemplazar la función print_table con la versión optimizada
    new_content = re.sub(print_table_pattern, optimized_print_table, content)
    
    # Verificar si se necesita importar shutil
    if "import shutil" not in new_content:
        # Buscar sección de imports
        import_section_pattern = r"(import .*\n)+"
        import_section_match = re.search(import_section_pattern, new_content)
        
        if import_section_match:
            import_section = import_section_match.group(0)
            new_import_section = import_section + "import shutil\n"
            new_content = new_content.replace(import_section, new_import_section)
        else:
            # Si no se encuentra una sección de imports, añadir al principio
            new_content = "import shutil\n" + new_content
    
    # Guardar cambios
    with open(printer_path, "w") as f:
        f.write(new_content)
    
    print("[+] Módulo printer.py optimizado correctamente")
    return True

def main():
    print("[*] Optimización para pantallas pequeñas en RouterSploit")
    
    # Verificar directorio RouterSploit
    if not os.path.exists(os.path.join(base_dir, "rsf.py")):
        print(f"[-] Error: No se encontró RouterSploit en {base_dir}")
        return
    
    # Verificar permisos de escritura
    if not os.access(printer_path, os.W_OK):
        print(f"[-] Error: No tienes permisos de escritura en {printer_path}")
        return
    
    # Parchear módulo printer
    if patch_printer_module():
        print("[+] Optimización completada correctamente")
        print("[*] Ahora RouterSploit se verá mejor en pantallas pequeñas")
        print("[*] Para probar, ejecuta RouterSploit y utiliza comandos que muestren tablas")
    else:
        print("[-] Error al aplicar optimizaciones")

if __name__ == "__main__":
    main()
