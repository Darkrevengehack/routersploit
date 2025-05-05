#!/usr/bin/env python3

import os
import re
import json
import time
import requests
import configparser
from datetime import datetime, timedelta
from routersploit.core.exploit.printer import print_info, print_error, print_success, print_status

CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "modules", "exploits", "routers")
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")

# Intentar cargar la API key desde el archivo de configuración
API_KEY = ""
try:
    if os.path.exists(CONFIG_FILE):
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        if 'nvd' in config and 'api_key' in config['nvd']:
            API_KEY = config['nvd']['api_key']
except Exception:
    pass

# Asegurarse de que el directorio de plantillas existe
if not os.path.exists(TEMPLATE_PATH):
    os.makedirs(TEMPLATE_PATH)

class CVEUpdater:
    def __init__(self):
        self.routers_vendors = [
            "tp-link", "netgear", "d-link", "asus", "linksys", "belkin", 
            "tenda", "xiaomi", "huawei", "zyxel", "mikrotik", "cisco",
            "arris", "ubiquiti", "actiontec", "technicolor", "movistar",
            "telecentro", "fibercorp", "personal", "claro"
        ]
        self.session = requests.Session()
        if API_KEY:
            self.session.headers.update({"apiKey": API_KEY})
        
    def search_recent_cves(self, days_back=30):
        """Busca CVEs recientes relacionados con routers"""
        print_status(f"Buscando CVEs de los últimos {days_back} días...")
        
        start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")
        end_date = datetime.now().strftime("%Y-%m-%d")
        
        all_cves = []
        
        for vendor in self.routers_vendors:
            retries = 3  # Número de intentos
            delay = 5    # Tiempo de espera inicial entre intentos (segundos)
            
            for attempt in range(retries):
                try:
                    print_status(f"Buscando vulnerabilidades para {vendor}...")
                    
                    # Parámetros de búsqueda
                    params = {
                        "pubStartDate": f"{start_date}T00:00:00.000",
                        "pubEndDate": f"{end_date}T23:59:59.999",
                        "keywordSearch": vendor,
                        "resultsPerPage": 50
                    }
                    
                    response = self.session.get(CVE_API_URL, params=params)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Filtrar solo vulnerabilidades de routers
                        for vuln in data.get("vulnerabilities", []):
                            cve_item = vuln.get("cve", {})
                            cve_id = cve_item.get("id", "")
                            
                            descriptions = cve_item.get("descriptions", [])
                            description = next((item.get("value", "") for item in descriptions 
                                            if item.get("lang") == "en"), "")
                            
                            # Verificar si es relevante para routers
                            if any(keyword in description.lower() for keyword in ["router", "gateway", "cpe", "modem", "wifi"]):
                                metrics = cve_item.get("metrics", {}).get("cvssMetricV3", [{}])[0].get("cvssData", {})
                                
                                cve_data = {
                                    "id": cve_id,
                                    "description": description,
                                    "published": cve_item.get("published", ""),
                                    "vendor": vendor,
                                    "severity": metrics.get("baseScore", 0),
                                    "attack_vector": metrics.get("attackVector", ""),
                                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                                }
                                
                                all_cves.append(cve_data)
                        
                        # Si la solicitud fue exitosa, pasar al siguiente vendor
                        break
                    
                    elif response.status_code == 403:
                        print_error(f"Error 403 al buscar CVEs para {vendor}. Reintentando en {delay} segundos...")
                        time.sleep(delay)
                        # Aumentar el tiempo de espera para el próximo intento (backoff exponencial)
                        delay *= 2
                        
                        # Si es el último intento, mostrar el error
                        if attempt == retries - 1:
                            print_error(f"Error al buscar CVEs para {vendor}: {response.status_code}")
                    
                    else:
                        print_error(f"Error al buscar CVEs para {vendor}: {response.status_code}")
                        break
                
                except Exception as e:
                    print_error(f"Error al procesar CVEs para {vendor}: {str(e)}")
                    break
            
            # Esperar entre diferentes fabricantes para evitar sobrecargar la API
            # Este tiempo es adicional al reintento en caso de error
            time.sleep(3)
        
        print_success(f"Se encontraron {len(all_cves)} CVEs relacionados con routers")
        return all_cves
    
    def generate_module_template(self, cve_data):
        """Genera una plantilla de módulo a partir de los datos de CVE"""
        vendor = cve_data["vendor"]
        module_path = os.path.join(OUTPUT_PATH, vendor)
        
        # Asegurarse de que existe el directorio para el vendedor
        if not os.path.exists(module_path):
            os.makedirs(module_path)
        
        # Generar un nombre de archivo basado en el CVE
        cve_id_clean = cve_data["id"].replace("-", "_").lower()
        module_name = f"{vendor}_{cve_id_clean}.py"
        module_file = os.path.join(module_path, module_name)
        
        # No sobreescribir si ya existe
        if os.path.exists(module_file):
            print_info(f"El módulo para {cve_data['id']} ya existe en {module_file}")
            return None
        
        # Determinar el tipo de vulnerabilidad basado en la descripción
        vuln_type = "generic"
        description = cve_data["description"].lower()
        
        if "command injection" in description or "os command" in description or "rce" in description:
            vuln_type = "command_injection"
        elif "sql injection" in description:
            vuln_type = "sqli"
        elif "cross site" in description or "xss" in description:
            vuln_type = "xss"
        elif "buffer overflow" in description or "buffer over-read" in description:
            vuln_type = "buffer_overflow"
        elif "path traversal" in description or "directory traversal" in description:
            vuln_type = "path_traversal"
        elif "authentication bypass" in description or "auth bypass" in description:
            vuln_type = "auth_bypass"
        
        # Cargar la plantilla adecuada
        template_file = os.path.join(TEMPLATE_PATH, f"{vuln_type}_template.py")
        if not os.path.exists(template_file):
            template_file = os.path.join(TEMPLATE_PATH, "generic_template.py")
        
        with open(template_file, "r") as f:
            template = f.read()
        
        # Reemplazar variables en la plantilla
        replacements = {
            "{{CVE_ID}}": cve_data["id"],
            "{{DESCRIPTION}}": cve_data["description"],
            "{{VENDOR}}": vendor,
            "{{DATE}}": datetime.now().strftime("%Y-%m-%d"),
            "{{SEVERITY}}": str(cve_data["severity"]),
            "{{REFERENCES}}": cve_data["url"]
        }
        
        for key, value in replacements.items():
            template = template.replace(key, value)
        
        # Guardar el nuevo módulo
        with open(module_file, "w") as f:
            f.write(template)
        
        print_success(f"Módulo generado: {module_file}")
        return module_file
    
    def create_templates_if_not_exist(self):
        """Crea las plantillas base si no existen"""
        templates = {
            "generic_template.py": """#!/usr/bin/env python3

from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient

class Exploit(HTTPClient):
    __info__ = {
        "name": "{{VENDOR}} Router Vulnerability",
        "description": "{{DESCRIPTION}}",
        "authors": [
            "Unknown",  # Vulnerability discovery
            "Auto-generated by CVE Updater",  # Routersploit module
        ],
        "references": [
            "{{REFERENCES}}",
        ],
        "devices": [
            "{{VENDOR}} Router",
        ],
        "date": "{{DATE}}",
        "cve": "{{CVE_ID}}",
        "severity": "{{SEVERITY}}"
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")
    ssl = OptBool(False, "SSL enabled: true/false")
    username = OptString("admin", "Default username")
    password = OptString("admin", "Default password")
    
    def run(self):
        # Esta es una plantilla generada automáticamente y requiere implementación manual
        print_status("Este módulo fue generado automáticamente basado en un CVE reciente")
        print_status("Se requiere implementación manual para completar el exploit")
        print_status("Detalles del CVE:")
        print_info(f"CVE: {{CVE_ID}}")
        print_info(f"Descripción: {{DESCRIPTION}}")
        print_info(f"Referencias: {{REFERENCES}}")
        return
    
    def check(self):
        # Código para verificar si el dispositivo es vulnerable
        return False  # Implementación pendiente
""",
            "command_injection_template.py": """#!/usr/bin/env python3

from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient

class Exploit(HTTPClient):
    __info__ = {
        "name": "{{VENDOR}} Router Command Injection",
        "description": "{{DESCRIPTION}}",
        "authors": [
            "Unknown",  # Vulnerability discovery
            "Auto-generated by CVE Updater",  # Routersploit module
        ],
        "references": [
            "{{REFERENCES}}",
        ],
        "devices": [
            "{{VENDOR}} Router",
        ],
        "date": "{{DATE}}",
        "cve": "{{CVE_ID}}",
        "severity": "{{SEVERITY}}"
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")
    ssl = OptBool(False, "SSL enabled: true/false")
    username = OptString("admin", "Default username")
    password = OptString("admin", "Default password")
    
    def run(self):
        # Esta es una plantilla generada automáticamente para command injection
        if self.check():
            print_success("El dispositivo es vulnerable a inyección de comandos")
            print_status("Iniciando shell interactivo...")
            
            while True:
                cmd = input("# ")
                if cmd in ["exit", "quit"]:
                    return
                
                print_status("Ejecutando comando: {}".format(cmd))
                # Aquí iría el código para ejecutar el comando
                print_status("Implementación pendiente - necesita desarrollo manual")
        else:
            print_error("El dispositivo no parece ser vulnerable")
    
    def check(self):
        # Código para verificar si el dispositivo es vulnerable
        return False  # Implementación pendiente
""",
            "sqli_template.py": """#!/usr/bin/env python3

from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient

class Exploit(HTTPClient):
    __info__ = {
        "name": "{{VENDOR}} Router SQL Injection",
        "description": "{{DESCRIPTION}}",
        "authors": [
            "Unknown",  # Vulnerability discovery
            "Auto-generated by CVE Updater",  # Routersploit module
        ],
        "references": [
            "{{REFERENCES}}",
        ],
        "devices": [
            "{{VENDOR}} Router",
        ],
        "date": "{{DATE}}",
        "cve": "{{CVE_ID}}",
        "severity": "{{SEVERITY}}"
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")
    ssl = OptBool(False, "SSL enabled: true/false")
    username = OptString("admin", "Default username")
    password = OptString("admin", "Default password")
    
    def run(self):
        # Esta es una plantilla generada automáticamente para SQL Injection
        if self.check():
            print_success("El dispositivo es vulnerable a SQL Injection")
            print_status("Se requiere implementación manual para explotar esta vulnerabilidad")
        else:
            print_error("El dispositivo no parece ser vulnerable")
    
    def check(self):
        # Código para verificar si el dispositivo es vulnerable
        return False  # Implementación pendiente
""",
            "xss_template.py": """#!/usr/bin/env python3

from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient

class Exploit(HTTPClient):
    __info__ = {
        "name": "{{VENDOR}} Router Cross-Site Scripting",
        "description": "{{DESCRIPTION}}",
        "authors": [
            "Unknown",  # Vulnerability discovery
            "Auto-generated by CVE Updater",  # Routersploit module
        ],
        "references": [
            "{{REFERENCES}}",
        ],
        "devices": [
            "{{VENDOR}} Router",
        ],
        "date": "{{DATE}}",
        "cve": "{{CVE_ID}}",
        "severity": "{{SEVERITY}}"
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")
    ssl = OptBool(False, "SSL enabled: true/false")
    path = OptString("/", "Path to vulnerable page")
    parameter = OptString("", "Vulnerable parameter")
    
    def run(self):
        # Esta es una plantilla generada automáticamente para XSS
        if self.check():
            print_success("El dispositivo es vulnerable a Cross-Site Scripting")
            print_status("Se requiere implementación manual para explotar esta vulnerabilidad")
            
            # Generar URL de prueba XSS
            xss_payload = "<script>alert('XSS')</script>"
            url = "{}://{}:{}{}"
            protocol = "https" if self.ssl else "http"
            
            if self.parameter:
                test_url = url.format(protocol, self.target, self.port, self.path)
                test_url += "?" + self.parameter + "=" + xss_payload
                print_info("URL de prueba: {}".format(test_url))
            else:
                print_status("Especifica un parámetro vulnerable utilizando 'set parameter <nombre>'")
        else:
            print_error("El dispositivo no parece ser vulnerable")
    
    def check(self):
        # Código para verificar si el dispositivo es vulnerable
        return False  # Implementación pendiente
""",
            "path_traversal_template.py": """#!/usr/bin/env python3

from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient

class Exploit(HTTPClient):
    __info__ = {
        "name": "{{VENDOR}} Router Path Traversal",
        "description": "{{DESCRIPTION}}",
        "authors": [
            "Unknown",  # Vulnerability discovery
            "Auto-generated by CVE Updater",  # Routersploit module
        ],
        "references": [
            "{{REFERENCES}}",
        ],
        "devices": [
            "{{VENDOR}} Router",
        ],
        "date": "{{DATE}}",
        "cve": "{{CVE_ID}}",
        "severity": "{{SEVERITY}}"
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")
    ssl = OptBool(False, "SSL enabled: true/false")
    path = OptString("/", "Base path")
    depth = OptInteger(5, "Traversal depth (../../../)")
    file = OptString("/etc/passwd", "File to read")
    
    def run(self):
        # Esta es una plantilla generada automáticamente para Path Traversal
        if self.check():
            print_success("El dispositivo es vulnerable a Path Traversal")
            
            # Generar payload de traversal
            traversal = "../" * self.depth
            traversal_url = "{}://{}:{}{}{}"
            protocol = "https" if self.ssl else "http"
            
            url = traversal_url.format(protocol, self.target, self.port, self.path, traversal + self.file)
            print_status("Intentando leer archivo: {}".format(self.file))
            print_info("URL: {}".format(url))
            
            # Aquí iría el código para intentar obtener el archivo
            print_status("Implementación pendiente - necesita desarrollo manual")
        else:
            print_error("El dispositivo no parece ser vulnerable")
    
    def check(self):
        # Código para verificar si el dispositivo es vulnerable
        return False  # Implementación pendiente
""",
            "auth_bypass_template.py": """#!/usr/bin/env python3

from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient

class Exploit(HTTPClient):
    __info__ = {
        "name": "{{VENDOR}} Router Authentication Bypass",
        "description": "{{DESCRIPTION}}",
        "authors": [
            "Unknown",  # Vulnerability discovery
            "Auto-generated by CVE Updater",  # Routersploit module
        ],
        "references": [
            "{{REFERENCES}}",
        ],
        "devices": [
            "{{VENDOR}} Router",
        ],
        "date": "{{DATE}}",
        "cve": "{{CVE_ID}}",
        "severity": "{{SEVERITY}}"
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")
    ssl = OptBool(False, "SSL enabled: true/false")
    path = OptString("/", "Path to admin panel")
    
    def run(self):
        # Esta es una plantilla generada automáticamente para Authentication Bypass
        if self.check():
            print_success("El dispositivo es vulnerable a Authentication Bypass")
            
            admin_url = "{}://{}:{}{}"
            protocol = "https" if self.ssl else "http"
            url = admin_url.format(protocol, self.target, self.port, self.path)
            
            print_status("URL de la interfaz de administración: {}".format(url))
            print_status("Técnica de bypass: [Implementación pendiente]")
            
            # Aquí iría el código para ejecutar el bypass
            print_status("Implementación pendiente - necesita desarrollo manual")
        else:
            print_error("El dispositivo no parece ser vulnerable")
    
    def check(self):
        # Código para verificar si el dispositivo es vulnerable
        return False  # Implementación pendiente
""",
            "buffer_overflow_template.py": """#!/usr/bin/env python3

from routersploit.core.exploit import *
from routersploit.core.tcp.tcp_client import TCPClient

class Exploit(TCPClient):
    __info__ = {
        "name": "{{VENDOR}} Router Buffer Overflow",
        "description": "{{DESCRIPTION}}",
        "authors": [
            "Unknown",  # Vulnerability discovery
            "Auto-generated by CVE Updater",  # Routersploit module
        ],
        "references": [
            "{{REFERENCES}}",
        ],
        "devices": [
            "{{VENDOR}} Router",
        ],
        "date": "{{DATE}}",
        "cve": "{{CVE_ID}}",
        "severity": "{{SEVERITY}}"
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target port")
    payload_size = OptInteger(1024, "Tamaño del payload")
    
    def run(self):
        # Esta es una plantilla generada automáticamente para Buffer Overflow
        if self.check():
            print_success("El dispositivo podría ser vulnerable a Buffer Overflow")
            
            # Generar payload de prueba
            payload = b"A" * self.payload_size
            
            print_status(f"Enviando payload de {self.payload_size} bytes a {self.target}:{self.port}")
            
            # Aquí iría el código para enviar el payload
            print_status("Implementación pendiente - necesita desarrollo manual")
            print_info("ADVERTENCIA: Este tipo de exploit puede causar la caída del dispositivo")
        else:
            print_error("El dispositivo no parece ser vulnerable")
    
    def check(self):
        # Código para verificar si el dispositivo es vulnerable
        return False  # Implementación pendiente
"""
        }
        
        for filename, content in templates.items():
            template_file = os.path.join(TEMPLATE_PATH, filename)
            if not os.path.exists(template_file):
                with open(template_file, "w") as f:
                    f.write(content)
                print_info(f"Plantilla creada: {filename}")

def run():
    """Función principal para ejecutar el actualizador desde línea de comandos"""
    updater = CVEUpdater()
    updater.create_templates_if_not_exist()
    
    # Verificar si se tiene API key
    global API_KEY
    if not API_KEY:
        print_info("No se ha configurado una API key para la NVD")
        print_info("Para mejorar los resultados y evitar errores 403, puedes obtener una API key gratuita en:")
        print_info("https://nvd.nist.gov/developers/request-an-api-key")
        
        use_key = input("[+] ¿Deseas ingresar una API key ahora? (s/n): ")
        if use_key.lower() == "s":
            API_KEY = input("[+] Ingresa tu API key: ").strip()
            updater.session.headers.update({"apiKey": API_KEY})
            
            save_key = input("[+] ¿Guardar esta API key para futuras sesiones? (s/n): ")
            
            if save_key.lower() == "s":
                try:
                    config = configparser.ConfigParser()
                    if not os.path.exists(CONFIG_FILE):
                        config['nvd'] = {}
                    else:
                        config.read(CONFIG_FILE)
                        if 'nvd' not in config:
                            config['nvd'] = {}
                    
                    config['nvd']['api_key'] = API_KEY
                    
                    with open(CONFIG_FILE, 'w') as f:
                        config.write(f)
                    
                    print_success("API key guardada en config.ini")
                except Exception as e:
                    print_error(f"Error al guardar la API key: {str(e)}")
    
    # Buscar CVEs recientes
    days = input("[+] Buscar CVEs de los últimos X días (predeterminado: 30): ")
    days = int(days) if days.isdigit() else 30
    
    cves = updater.search_recent_cves(days)
    
    # Ordenar por severidad
    cves.sort(key=lambda x: float(x["severity"]) if x["severity"] else 0, reverse=True)
    
    # Mostrar los CVEs encontrados
    print_status("\nCVEs relevantes encontrados:")
    for i, cve in enumerate(cves[:15], 1):  # Mostrar solo los primeros 15
        print_info(f"{i}. {cve['id']} ({cve['vendor']}) - Severidad: {cve['severity']}")
        print_info(f"   {cve['description'][:100]}...")
    
    # Preguntar cuáles generar
    selection = input("\n[+] Generar plantillas para todos los CVEs? (s/n, predeterminado: n): ")
    
    if selection.lower() == "s":
        for cve in cves:
            updater.generate_module_template(cve)
    else:
        print_status("Ingrese los números de los CVEs para generar plantillas (separados por coma):")
        selection = input("[+] Selección: ")
        
        try:
            if selection.strip():
                indices = [int(x.strip()) - 1 for x in selection.split(",")]
                for idx in indices:
                    if 0 <= idx < len(cves):
                        updater.generate_module_template(cves[idx])
                    else:
                        print_error(f"Índice fuera de rango: {idx + 1}")
        except ValueError:
            print_error("Entrada inválida. Use números separados por comas.")

if __name__ == "__main__":
    run()
