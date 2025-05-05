#!/usr/bin/env python3

import ssl
import socket
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
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
        self.vulnerable_protocols = [
            ssl.PROTOCOL_SSLv2,
            ssl.PROTOCOL_SSLv3,
            ssl.PROTOCOL_TLSv1,
        ]
        
        # Nombres amigables de protocolos
        self.protocol_names = {
            ssl.PROTOCOL_SSLv2: "SSLv2",
            ssl.PROTOCOL_SSLv3: "SSLv3",
            ssl.PROTOCOL_TLSv1: "TLSv1.0",
            ssl.PROTOCOL_TLSv1_1: "TLSv1.1",
            ssl.PROTOCOL_TLSv1_2: "TLSv1.2",
        }
        
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
        
        for protocol in self.vulnerable_protocols + [ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1_2]:
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
                            vuln = {
                                "name": f"Protocolo vulnerable {version}",
                                "severity": "Alta" if protocol in [ssl.PROTOCOL_SSLv2, ssl.PROTOCOL_SSLv3] else "Media",
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
    
    def check_heartbleed(self):
        """Comprobar la vulnerabilidad Heartbleed (CVE-2014-0160)"""
        print_status("Comprobando vulnerabilidad Heartbleed...")
        
        try:
            # Implementación simplificada del test de Heartbleed
            # Para una verificación completa se necesitaría enviar un paquete heartbeat malformado
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
            
            # Obtener versión de OpenSSL
            version = ssl_sock.version()
            ssl_sock.close()
            
            print_info(f"Versión SSL/TLS: {version}")
            
            # Versiones vulnerables de OpenSSL (simplificado)
            if "1.0.1" in version and not any(v in version for v in ["1.0.1g", "1.0.1h", "1.0.1i"]):
                vuln = {
                    "name": "Posible vulnerabilidad Heartbleed (CVE-2014-0160)",
                    "severity": "Crítica",
                    "description": "El servidor podría ser vulnerable a Heartbleed basado en la versión de OpenSSL"
                }
                self.vulnerabilities.append(vuln)
                print_info("El servidor podría ser vulnerable a Heartbleed")
            else:
                print_info("El servidor no parece vulnerable a Heartbleed")
                
        except Exception as e:
            print_error(f"Error al verificar Heartbleed: {str(e)}")
    
    def check_ccs_injection(self):
        """Comprobar la vulnerabilidad CCS Injection (CVE-2014-0224)"""
        print_status("Comprobando vulnerabilidad CCS Injection...")
        
        # Esta es una comprobación basada en heurística - una prueba real requeriría enviar un CCS durante el handshake
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
            version = ssl_sock.version()
            ssl_sock.close()
            
            # Versiones vulnerables de OpenSSL (simplificado)
            if "1.0.1" in version and not any(v in version for v in ["1.0.1h", "1.0.1i"]):
                vuln = {
                    "name": "Posible vulnerabilidad CCS Injection (CVE-2014-0224)",
                    "severity": "Alta",
                    "description": "El servidor podría ser vulnerable a CCS Injection basado en la versión de OpenSSL"
                }
                self.vulnerabilities.append(vuln)
                print_info("El servidor podría ser vulnerable a CCS Injection")
            else:
                print_info("El servidor no parece vulnerable a CCS Injection")
                
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
            context.set_ciphers("RSA")
            
            try:
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
                    # Obtener certificado en formato DER
                    cert_der = ssl_sock.getpeercert(binary_form=True)
                    
                    if not cert_der:
                        print_error("No se pudo obtener el certificado")
                        return
                    
                    # Parsear certificado
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    # Obtener información del certificado
                    self.cert_info = {
                        "subject": str(cert.subject),
                        "issuer": str(cert.issuer),
                        "serial_number": cert.serial_number,
                        "not_valid_before": cert.not_valid_before,
                        "not_valid_after": cert.not_valid_after,
                        "signature_algorithm": cert.signature_algorithm_oid._name,
                        "fingerprint": hashlib.sha256(cert_der).hexdigest(),
                    }
                    
                    # Verificar problemas con el certificado
                    self.verify_certificate_issues(cert)
        
        except Exception as e:
            print_error(f"Error al analizar certificado: {str(e)}")
    
    def verify_certificate_issues(self, cert):
        """Verificar problemas comunes en certificados"""
        from datetime import datetime
        
        now = datetime.now()
        
        # Verificar fecha de caducidad
        if cert.not_valid_after < now:
            vuln = {
                "name": "Certificado caducado",
                "severity": "Alta",
                "description": f"El certificado expiró el {cert.not_valid_after}"
            }
            self.vulnerabilities.append(vuln)
            print_error(f"El certificado ha caducado: {cert.not_valid_after}")
        
        # Verificar si está próximo a caducar
        days_to_expire = (cert.not_valid_after - now).days
        if 0 < days_to_expire < 30:
            vuln = {
                "name": "Certificado próximo a caducar",
                "severity": "Media",
                "description": f"El certificado caducará en {days_to_expire} días"
            }
            self.vulnerabilities.append(vuln)
            print_info(f"El certificado caducará pronto: {days_to_expire} días")
        
        # Verificar algoritmo de firma
        weak_algorithms = ["md5", "sha1"]
        for algo in weak_algorithms:
            if algo in str(cert.signature_algorithm_oid._name).lower():
                vuln = {
                    "name": f"Algoritmo de firma débil ({algo})",
                    "severity": "Alta",
                    "description": f"El certificado utiliza el algoritmo de firma débil {algo}"
                }
                self.vulnerabilities.append(vuln)
                print_error(f"Algoritmo de firma débil: {cert.signature_algorithm_oid._name}")
    
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
