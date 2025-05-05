#!/usr/bin/env python3

import ssl
import socket
import hashlib
import struct
import time
from datetime import datetime
from routersploit.core.exploit import *
from routersploit.core.tcp.tcp_client import TCPClient

class Exploit(TCPClient):
    __info__ = {
        "name": "TLS/SSL Scanner",
        "description": "Escanea vulnerabilidades TLS/SSL en el objetivo",
        "authors": (
            "Autor RouterSploit",  # módulo
        ),
        "references": (
            "https://weakdh.org/",
            "https://heartbleed.com/",
            "https://robotattack.org/",
        ),
        "devices": (
            "Routers genéricos",
            "Dispositivos IoT",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(443, "Target TLS/SSL port")
    timeout = OptFloat(10.0, "Connection timeout in seconds")

    def __init__(self):
        self.vulnerabilities = []
        self.cert_info = {}
        
        # Lista de cifrados débiles
        self.weak_ciphers = [
            "TLS_RSA_WITH_RC4_128_SHA",
            "TLS_RSA_WITH_RC4_128_MD5",
            "TLS_RSA_WITH_DES_CBC_SHA",
            "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
            "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        ]
        
        # Protocolos vulnerables
        self.vulnerable_protocols = []
        # SSLv2 fue eliminado de versiones recientes de Python
        try:
            if hasattr(ssl, 'PROTOCOL_SSLv2'):
                self.vulnerable_protocols.append(ssl.PROTOCOL_SSLv2)
            # SSLv3 y TLSv1.0 son considerados inseguros
            if hasattr(ssl, 'PROTOCOL_SSLv3'):
                self.vulnerable_protocols.append(ssl.PROTOCOL_SSLv3)
            self.vulnerable_protocols.append(ssl.PROTOCOL_TLSv1)
        except AttributeError:
            pass
        
        # Nombres amigables de protocolos
        self.protocol_names = {}
        if hasattr(ssl, 'PROTOCOL_SSLv2'):
            self.protocol_names[ssl.PROTOCOL_SSLv2] = "SSLv2"
        if hasattr(ssl, 'PROTOCOL_SSLv3'):
            self.protocol_names[ssl.PROTOCOL_SSLv3] = "SSLv3"
        self.protocol_names[ssl.PROTOCOL_TLSv1] = "TLSv1.0"
        self.protocol_names[ssl.PROTOCOL_TLSv1_1] = "TLSv1.1"
        self.protocol_names[ssl.PROTOCOL_TLSv1_2] = "TLSv1.2"
        # Añadir TLSv1.3 si está disponible
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            self.protocol_names[ssl.PROTOCOL_TLSv1_3] = "TLSv1.3"
        
    def run(self):
        if not self.check():
            print_error("¡El servidor no tiene habilitado SSL/TLS!")
            return
        
        print_status("Iniciando análisis de seguridad TLS/SSL...")
        
        # Comprobar la versión del protocolo
        self.check_protocol_versions()
        
        # Comprobar cifrados débiles
        self.check_weak_ciphers()
        
        # Verificar vulnerabilidades conocidas
        self.check_heartbleed()
        self.check_ccs_injection()
        self.check_robot_attack()
        
        # Analizar certificado
        self.analyze_certificate()
        
        # Mostrar resultados
        self.print_results()
    
    def check(self):
        """Comprobar si el servidor tiene SSL/TLS habilitado"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            # Intentar establecer una conexión SSL
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
            ssl_sock.close()
            
            return True
        except Exception as e:
            print_error(f"Error de conexión: {str(e)}")
            return False
    
    def check_protocol_versions(self):
        """Comprobar qué versiones de protocolo están habilitadas"""
        print_status("Comprobando versiones de protocolo...")
        
        # Protocolos a comprobar (vulnerables + modernos)
        protocols_to_check = self.vulnerable_protocols + [ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1_2]
        # Añadir TLSv1.3 si está disponible
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            protocols_to_check.append(ssl.PROTOCOL_TLSv1_3)
            
        for protocol in protocols_to_check:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.connect((self.target, self.port))
                    
                    with context.wrap_socket(sock, server_hostname=self.target) as ssl_sock:
                        version = self.protocol_names.get(protocol, str(protocol))
                        print_info(f"Protocolo {version} habilitado")
                        
                        # Si es un protocolo vulnerable
                        if protocol in self.vulnerable_protocols:
                            severity = "Alta"
                            if hasattr(ssl, 'PROTOCOL_SSLv2') and protocol == ssl.PROTOCOL_SSLv2:
                                severity = "Alta"
                            elif hasattr(ssl, 'PROTOCOL_SSLv3') and protocol == ssl.PROTOCOL_SSLv3:
                                severity = "Alta"
                            else:
                                severity = "Media"
                                
                            vuln = {
                                "name": f"Protocolo vulnerable {version}",
                                "severity": severity,
                                "description": f"El servidor admite el protocolo {version} que es considerado inseguro"
                            }
                            self.vulnerabilities.append(vuln)
            
            except (ssl.SSLError, socket.error):
                # Este protocolo no está soportado
                version = self.protocol_names.get(protocol, str(protocol))
                print_info(f"Protocolo {version} no habilitado")
            except Exception as e:
                print_error(f"Error al verificar protocolo {protocol}: {str(e)}")
    
    def check_weak_ciphers(self):
        """Comprobar si se admiten cifrados débiles"""
        print_status("Comprobando cifrados débiles...")
        
        # Crear contexto TLS
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.target, self.port))
                
                with context.wrap_socket(sock, server_hostname=self.target) as ssl_sock:
                    # Obtener cifrado usado
                    cipher = ssl_sock.cipher()
                    if cipher:
                        print_info(f"Cifrado en uso: {cipher[0]}")
                        
                        if cipher[0] in self.weak_ciphers:
                            vuln = {
                                "name": "Cifrado débil en uso",
                                "severity": "Alta",
                                "description": f"El servidor utiliza el cifrado débil {cipher[0]}"
                            }
                            self.vulnerabilities.append(vuln)
        
        except Exception as e:
            print_error(f"Error al verificar cifrados: {str(e)}")
    
    # Métodos mejorados para detección de vulnerabilidades
            
    def create_heartbeat_payload(self):
        """Crea un payload para probar Heartbleed"""
        # Tipo de mensaje: heartbeat request (1)
        hb_type = b'\x01'
        # Versión TLS 1.1/1.2
        version = b'\x03\x02'
        # Longitud de payload: solicitamos 0x4000 (16384) bytes pero enviamos sólo unos pocos
        payload_length = b'\x40\x00'
        # Payload real (mucho menor que el solicitado)
        payload = b'HEARTBLEED-TEST-PAYLOAD'
        # Padding (mínimo 16 bytes según RFC)
        padding = b'\x00' * 16
        
        # Construir el registro TLS
        content_type = b'\x18'  # Heartbeat
        version = b'\x03\x02'  # TLS 1.1
        record_length = struct.pack('>H', len(hb_type + payload_length + payload + padding))
        
        # Mensaje heartbeat completo
        heartbeat_message = hb_type + payload_length + payload + padding
        
        # Registro TLS completo
        tls_record = content_type + version + record_length + heartbeat_message
        
        return tls_record
        
    def check_heartbleed(self):
        """Comprobar la vulnerabilidad Heartbleed (CVE-2014-0160) con método mejorado"""
        print_status("Comprobando vulnerabilidad Heartbleed...")
        
        # Este es un método más directo para comprobar Heartbleed
        try:
            # Crear socket y conectar
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            # Iniciar handshake TLS
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Wrap del socket
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target, do_handshake_on_connect=True)
            
            # Obtener versión de OpenSSL del servidor si es posible
            version = ssl_sock.version()
            print_info(f"Versión SSL/TLS: {version}")
            
            # Versiones vulnerables de OpenSSL
            if ("1.0.1" in version and 
                not any(v in version for v in ["1.0.1g", "1.0.1h", "1.0.1i", "1.0.1j", "1.0.1k", "1.0.1l"])):
                vuln = {
                    "name": "Posible vulnerabilidad Heartbleed (CVE-2014-0160)",
                    "severity": "Crítica",
                    "description": "El servidor podría ser vulnerable a Heartbleed basado en la versión de OpenSSL"
                }
                self.vulnerabilities.append(vuln)
                print_info("El servidor podría ser vulnerable a Heartbleed")
            else:
                # Comprobar comportamiento incluso si la versión no es conocida como vulnerable
                try:
                    # Método alternativo: comprobar soporte de extensión heartbeat
                    has_heartbeat = False
                    for ext in ssl_sock.get_peer_cert().get('extensions', []):
                        if 'heartbeat' in ext:
                            has_heartbeat = True
                            break
                    
                    if has_heartbeat:
                        print_info("El servidor soporta extensión heartbeat, realizando prueba...")
                        
                        # Cerrar la conexión actual y abrir una nueva para la prueba real
                        ssl_sock.close()
                        sock.close()
                        
                        # Nueva conexión para probar directamente
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.timeout)
                        sock.connect((self.target, self.port))
                        
                        # Handshake SSL/TLS básico
                        ssl_sock = context.wrap_socket(sock, server_hostname=self.target, do_handshake_on_connect=True)
                        
                        # Enviar payload heartbeat malformado
                        heartbleed_payload = self.create_heartbeat_payload()
                        ssl_sock.write(heartbleed_payload)
                        
                        # Leer respuesta (vulnerable si devuelve más datos de los que debería)
                        try:
                            response = ssl_sock.read(20000)  # Leer bastante para ver si devuelve datos de memoria
                            
                            # Si la respuesta es mucho mayor que nuestro payload, podría ser vulnerable
                            if len(response) > 100:  # Valor arbitrario, ajustar según sea necesario
                                vuln = {
                                    "name": "Vulnerabilidad Heartbleed detectada (CVE-2014-0160)",
                                    "severity": "Crítica",
                                    "description": "El servidor es vulnerable a Heartbleed y devolvió datos de memoria"
                                }
                                self.vulnerabilities.append(vuln)
                                print_error("¡El servidor es vulnerable a Heartbleed!")
                            else:
                                print_info("El servidor no parece vulnerable a Heartbleed")
                        except Exception as e:
                            # Si el servidor cierra la conexión o hay otro error, probablemente no es vulnerable
                            print_info(f"El servidor no parece vulnerable a Heartbleed: {str(e)}")
                    else:
                        print_info("El servidor no soporta extensión heartbeat, no vulnerable a Heartbleed")
                except Exception as e:
                    print_info("No se pudo determinar si es vulnerable a Heartbleed mediante prueba directa")
                    print_info(f"Error en prueba: {str(e)}")
                
        except ssl.SSLError as e:
            if "handshake failure" in str(e).lower() or "alert" in str(e).lower():
                print_info("El servidor rechazó la conexión - probablemente no vulnerable a Heartbleed")
            else:
                print_error(f"Error SSL al verificar Heartbleed: {str(e)}")
        except Exception as e:
            print_error(f"Error al verificar Heartbleed: {str(e)}")
    
    def check_ccs_injection(self):
        """Comprobar la vulnerabilidad CCS Injection (CVE-2014-0224) con método mejorado"""
        print_status("Comprobando vulnerabilidad CCS Injection...")
        
        try:
            # Crear socket y conectar
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            # Iniciar handshake TLS
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Wrap del socket
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
            
            # Obtener versión de OpenSSL
            version = ssl_sock.version()
            print_info(f"Versión SSL/TLS: {version}")
            
            # Verificar versión vulnerable
            # OpenSSL versiones vulnerables: 0.9.8 hasta 0.9.8za, 1.0.0 hasta 1.0.0l, 1.0.1 hasta 1.0.1g
            is_vulnerable = False
            
            if "OpenSSL" in version:
                if ("0.9.8" in version and not "0.9.8zb" in version) or \
                   ("1.0.0" in version and not any(v in version for v in ["1.0.0m", "1.0.0n", "1.0.0o", "1.0.0p"])) or \
                   ("1.0.1" in version and not any(v in version for v in ["1.0.1h", "1.0.1i", "1.0.1j", "1.0.1k"])):
                    is_vulnerable = True
            
            if is_vulnerable:
                vuln = {
                    "name": "Posible vulnerabilidad CCS Injection (CVE-2014-0224)",
                    "severity": "Alta",
                    "description": "El servidor podría ser vulnerable a CCS Injection basado en la versión de OpenSSL"
                }
                self.vulnerabilities.append(vuln)
                print_error("¡El servidor podría ser vulnerable a CCS Injection!")
            else:
                # Prueba alternativa basada en comportamiento
                try:
                    # Cerrar conexión actual
                    ssl_sock.close()
                    sock.close()
                    
                    # Nueva conexión para prueba directa
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((self.target, self.port))
                    
                    # Mensaje CCS (Change Cipher Spec) prematuro
                    # Tipo de mensaje: Change Cipher Spec (20)
                    content_type = b'\x14'
                    # Versión TLS 1.0
                    version = b'\x03\x01'
                    # Longitud del mensaje
                    length = b'\x00\x01'
                    # CCS payload (1)
                    payload = b'\x01'
                    
                    # Construir y enviar mensaje CCS
                    ccs_message = content_type + version + length + payload
                    sock.send(ccs_message)
                    
                    # Si es vulnerable, podría aceptar el mensaje y continuar
                    # Si no es vulnerable, debería cerrar la conexión
                    time.sleep(0.5)  # Esperar respuesta
                    
                    try:
                        # Intentar enviar otro mensaje (handshake)
                        sock.send(b"\x16\x03\x01\x00\x01\x01")
                        response = sock.recv(1024)
                        
                        # Si llegamos aquí sin error, podría ser vulnerable
                        if response and len(response) > 0:
                            vuln = {
                                "name": "Posible vulnerabilidad CCS Injection (CVE-2014-0224)",
                                "severity": "Alta",
                                "description": "El servidor podría ser vulnerable a CCS Injection (prueba directa)"
                            }
                            self.vulnerabilities.append(vuln)
                            print_error("¡El servidor podría ser vulnerable a CCS Injection (prueba directa)!")
                        else:
                            print_info("El servidor no parece vulnerable a CCS Injection")
                    except Exception:
                        # Si se produce un error al enviar/recibir, probablemente no es vulnerable
                        print_info("El servidor no parece vulnerable a CCS Injection")
                except Exception as e:
                    print_info(f"No se pudo determinar si es vulnerable a CCS Injection mediante prueba directa: {str(e)}")
                    
        except ssl.SSLError as e:
            print_info(f"El servidor rechazó la conexión - probablemente no vulnerable a CCS Injection: {str(e)}")
        except Exception as e:
            print_error(f"Error al verificar CCS Injection: {str(e)}")
    
    def check_robot_attack(self):
        """Comprobar la vulnerabilidad ROBOT (Return Of Bleichenbacher's Oracle Threat)"""
        print_status("Comprobando vulnerabilidad ROBOT...")
        
        # Esta es una verificación simplificada - una prueba real requeriría enviar múltiples handshakes con padding malformado
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Intentar con cifrados RSA
            try:
                context.set_ciphers("RSA")
                
                ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
                cipher = ssl_sock.cipher()
                ssl_sock.close()
                
                if cipher and "RSA" in cipher[0]:
                    print_info(f"El servidor utiliza cifrados RSA: {cipher[0]}")
                    print_info("El servidor podría ser vulnerable a ROBOT, se requiere prueba adicional")
                    
                    vuln = {
                        "name": "Posible vulnerabilidad ROBOT",
                        "severity": "Alta",
                        "description": "El servidor utiliza cifrados RSA que podrían ser vulnerables a ROBOT"
                    }
                    self.vulnerabilities.append(vuln)
            except ssl.SSLError:
                print_info("El servidor no parece usar cifrados RSA vulnerables a ROBOT")
                
        except Exception as e:
            print_error(f"Error al verificar ROBOT: {str(e)}")
    
    def analyze_certificate(self):
        """Analizar el certificado SSL/TLS"""
        print_status("Analizando certificado SSL/TLS...")
        
        try:
            # Crear contexto y conectar
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, self.port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssl_sock:
                    # Obtener certificado
                    cert_bin = ssl_sock.getpeercert(binary_form=True)
                    cert = ssl_sock.getpeercert()
                    
                    if not cert:
                        print_error("No se pudo obtener el certificado")
                        return
                    
                    # Analizar certificado sin depender de cryptography
                    self.cert_info = {
                        "subject": str(cert.get('subject', [])),
                        "issuer": str(cert.get('issuer', [])),
                        "version": cert.get('version', ''),
                        "serialNumber": cert.get('serialNumber', ''),
                        "notBefore": cert.get('notBefore', ''),
                        "notAfter": cert.get('notAfter', ''),
                    }
                    
                    # Calcular hash del certificado
                    if cert_bin:
                        self.cert_info["sha256"] = hashlib.sha256(cert_bin).hexdigest()
                    
                    # Verificar problemas con el certificado
                    self.verify_certificate_issues(cert)
        
        except Exception as e:
            print_error(f"Error al analizar certificado: {str(e)}")
    
    def verify_certificate_issues(self, cert):
        """Verificar problemas comunes en certificados"""
        try:
            # Formato de fecha en certificados
            date_fmt = r'%b %d %H:%M:%S %Y %Z'
            
            now = datetime.now()
            
            # Verificar fechas del certificado
            not_before = None
            not_after = None
            
            try:
                if cert.get('notBefore'):
                    not_before = datetime.strptime(cert['notBefore'], date_fmt)
                if cert.get('notAfter'):
                    not_after = datetime.strptime(cert['notAfter'], date_fmt)
            except ValueError:
                # Formato alternativo de fecha (sin zona horaria)
                date_fmt = r'%b %d %H:%M:%S %Y'
                try:
                    if cert.get('notBefore'):
                        not_before = datetime.strptime(cert['notBefore'], date_fmt)
                    if cert.get('notAfter'):
                        not_after = datetime.strptime(cert['notAfter'], date_fmt)
                except ValueError:
                    print_error("No se pudieron analizar las fechas del certificado")
            
            # Verificar fecha de caducidad
            if not_after and not_after < now:
                vuln = {
                    "name": "Certificado caducado",
                    "severity": "Alta",
                    "description": f"El certificado expiró el {not_after}"
                }
                self.vulnerabilities.append(vuln)
                print_error(f"El certificado ha caducado: {not_after}")
            
            # Verificar si está próximo a caducar
            if not_after and now < not_after:
                days_to_expire = (not_after - now).days
                if days_to_expire < 30:
                    vuln = {
                        "name": "Certificado próximo a caducar",
                        "severity": "Media",
                        "description": f"El certificado caducará en {days_to_expire} días"
                    }
                    self.vulnerabilities.append(vuln)
                    print_info(f"El certificado caducará pronto: {days_to_expire} días")
            
            # Verificar si es un certificado autofirmado
            if cert.get('issuer') == cert.get('subject'):
                vuln = {
                    "name": "Certificado autofirmado",
                    "severity": "Media",
                    "description": "El servidor utiliza un certificado autofirmado, que no proporciona garantías de autenticidad"
                }
                self.vulnerabilities.append(vuln)
                print_info("El servidor utiliza un certificado autofirmado")
                
        except Exception as e:
            print_error(f"Error al verificar problemas del certificado: {str(e)}")
    
    def print_results(self):
        """Mostrar resultados del análisis"""
        print_status("\nResumen de vulnerabilidades encontradas:")
        
        if not self.vulnerabilities:
            print_success("No se encontraron vulnerabilidades TLS/SSL!")
            
        else:
            # Ordenar por severidad
            def severity_value(sev):
                values = {"Crítica": 4, "Alta": 3, "Media": 2, "Baja": 1, "Info": 0}
                return values.get(sev, 0)
            
            sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_value(x["severity"]), reverse=True)
            
            for i, vuln in enumerate(sorted_vulns, 1):
                print_error(f"{i}. [{vuln['severity']}] {vuln['name']}")
                print_info(f"   {vuln['description']}")
            
        # Mostrar información del certificado si está disponible
        if self.cert_info:
            print_status("\nInformación del certificado:")
            for key, value in self.cert_info.items():
                print_info(f"{key}: {value}")
