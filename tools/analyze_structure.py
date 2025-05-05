#!/usr/bin/env python3
# Analizador de estructura de RouterSploit

import os
import sys
import json

def analyze_structure():
    base_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    print(f"[*] Analizando estructura de RouterSploit en: {base_dir}")
    
    # Comprobar existencia de archivos principales
    main_files = ["rsf.py", "routersploit/interpreter.py", "routersploit/core/exploit/exploit.py"]
    print("\n[*] Verificando archivos principales:")
    for file in main_files:
        filepath = os.path.join(base_dir, file)
        if os.path.exists(filepath):
            print(f"[+] {file}: Encontrado")
        else:
            print(f"[-] {file}: No encontrado")
    
    # Analizar estructura de módulos
    modules_dir = os.path.join(base_dir, "routersploit/modules")
    if os.path.exists(modules_dir):
        print("\n[*] Estructura de módulos:")
        module_types = os.listdir(modules_dir)
        for module_type in module_types:
            type_path = os.path.join(modules_dir, module_type)
            if os.path.isdir(type_path):
                module_count = count_modules(type_path)
                print(f"[+] {module_type}: {module_count} módulos")
    
    # Analizar características principales
    print("\n[*] Analizando características principales:")
    check_optimizations(base_dir)

def count_modules(directory):
    count = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".py") and not file.startswith("__"):
                count += 1
    return count

def check_optimizations(base_dir):
    # Verificar si ya hay optimizaciones móviles
    rsf_path = os.path.join(base_dir, "rsf.py")
    mobile_optimized = False
    
    if os.path.exists(rsf_path):
        with open(rsf_path, "r") as f:
            content = f.read()
            if "mobile" in content.lower() or "termux" in content.lower():
                mobile_optimized = True
    
    if mobile_optimized:
        print("[+] Ya existen optimizaciones para móviles")
    else:
        print("[-] No se detectaron optimizaciones para móviles")
    
    # Verificar compatibilidad con pantallas pequeñas
    printer_path = os.path.join(base_dir, "routersploit/core/exploit/printer.py")
    screen_optimized = False
    
    if os.path.exists(printer_path):
        with open(printer_path, "r") as f:
            content = f.read()
            if "screen_width" in content or "terminal_width" in content:
                screen_optimized = True
    
    if screen_optimized:
        print("[+] Ya existe soporte para pantallas pequeñas")
    else:
        print("[-] No se detectó soporte para pantallas pequeñas")

if __name__ == "__main__":
    analyze_structure()
