#!/usr/bin/env python3

import socket
import time
import struct
from routersploit.core.exploit import *
from routersploit.core.tcp.tcp_client import TCPClient

class Exploit(TCPClient):
    __info__ = {
        "name": "MQTT Scanner",
        "description": "Escanea servidores MQTT en busca de configuraciones inseguras",
        "authors": (
            "Autor RouterSploit",  # módulo RouterSploit
        ),
        "references": (
            "https://www.hivemq.com/blog/mqtt-security-fundamentals/",
        ),
        "devices": (
            "Dispositivos IoT",
            "Brokers MQTT",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(1883, "Target MQTT port (default: 1883)")
    topics = OptString("$SYS/#,#", "Lista de tópicos a probar, separados por comas")
    check_auth = OptBool(True, "Intentar conexión sin autenticación")
    username = OptString("", "Nombre de usuario para autenticación")
    password = OptString("", "Contraseña para autenticación")
    timeout = OptFloat(8.0, "Tiempo de espera de conexión")
    
    def run(self):
        # Verificar si el puerto está abierto
        if not self.check():
            print_error(f"El puerto {self.port} está cerrado")
            return
        
        # Intentar conectar sin autenticación si está habilitado
        if self.check_auth:
            self.test_anonymous_access()
        
        # Probar acceso con credenciales si se proporcionaron
        if self.username or self.password:
            self.test_auth_access()
        
        # Probar temas comunes
        self.test_common_topics()
    
    def check(self):
        """Comprobar si el servidor MQTT está en línea"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            
            if result == 0:
                print_status(f"Puerto MQTT {self.port} está abierto")
                return True
            else:
                return False
        
        except Exception as e:
            print_error(f"Error al verificar puerto MQTT: {str(e)}")
            return False
    
    def create_connect_packet(self, client_id="RSPLOIT", username=None, password=None):
        """Crear un paquete MQTT CONNECT"""
        # Cabecera fija
        packet_type = 1  # CONNECT
        remaining_length = 0  # Se calculará después
        
        # Cabecera variable
        protocol_name = b"MQTT"
        protocol_level = 4  # MQTT v3.1.1
        connect_flags = 0
        
        if username:
            connect_flags |= 0x80  # Username flag
        if password:
            connect_flags |= 0x40  # Password flag
        
        connect_flags |= 0x02  # Clean session flag
        
        keep_alive = 60  # Segundos
        
        # Construir payload
        payload = bytearray()
        
        # Client ID
        payload.extend(struct.pack("!H", len(client_id)))
        payload.extend(client_id.encode())
        
        # Username (si está presente)
        if username:
            payload.extend(struct.pack("!H", len(username)))
            payload.extend(username.encode())
        
        # Password (si está presente)
        if password:
            payload.extend(struct.pack("!H", len(password)))
            payload.extend(password.encode())
        
        # Cabecera variable
        variable_header = bytearray()
        variable_header.extend(struct.pack("!H", len(protocol_name)))
        variable_header.extend(protocol_name)
        variable_header.append(protocol_level)
        variable_header.append(connect_flags)
        variable_header.extend(struct.pack("!H", keep_alive))
        
        # Calcular remaining_length
        remaining_length = len(variable_header) + len(payload)
        
        # Codificar remaining_length (formato variable)
        remaining_bytes = bytearray()
        while True:
            byte = remaining_length % 128
            remaining_length = remaining_length // 128
            if remaining_length > 0:
                byte |= 0x80
            remaining_bytes.append(byte)
            if remaining_length == 0:
                break
        
        # Construir el paquete completo
        packet = bytearray()
        packet.append(packet_type << 4)
        packet.extend(remaining_bytes)
        packet.extend(variable_header)
        packet.extend(payload)
        
        return packet
    
    def create_subscribe_packet(self, topic, packet_id=1):
        """Crear un paquete MQTT SUBSCRIBE"""
        # Cabecera fija
        packet_type = 8  # SUBSCRIBE
        remaining_length = 0  # Se calculará después
        
        # Cabecera variable
        variable_header = struct.pack("!H", packet_id)
        
        # Payload (tópicos)
        payload = bytearray()
        payload.extend(struct.pack("!H", len(topic)))
        payload.extend(topic.encode())
        payload.append(0)  # QoS 0
        
        # Calcular remaining_length
        remaining_length = len(variable_header) + len(payload)
        
        # Codificar remaining_length
        remaining_bytes = bytearray()
        while True:
            byte = remaining_length % 128
            remaining_length = remaining_length // 128
            if remaining_length > 0:
                byte |= 0x80
            remaining_bytes.append(byte)
            if remaining_length == 0:
                break
        
        # Construir el paquete completo
        packet = bytearray()
        packet.append((packet_type << 4) | 0x02)  # SUBSCRIBE con flag
        packet.extend(remaining_bytes)
        packet.extend(variable_header)
        packet.extend(payload)
        
        return packet
    
    def read_packet(self, sock):
        """Leer un paquete MQTT del socket"""
        try:
            # Leer cabecera fija (primer byte)
            header_byte = sock.recv(1)
            if not header_byte:
                return None
            
            # Leer remaining length
            multiplier = 1
            remaining_length = 0
            while True:
                byte = sock.recv(1)
                if not byte:
                    return None
                
                value = byte[0]
                remaining_length += (value & 127) * multiplier
                multiplier *= 128
                
                if not (value & 128):
                    break
            
            # Leer el resto del paquete
            if remaining_length > 0:
                packet = sock.recv(remaining_length)
                if len(packet) != remaining_length:
                    return None
            else:
                packet = b""
            
            # Determinar tipo de paquete
            packet_type = (header_byte[0] & 0xF0) >> 4
            
            return {
                "type": packet_type,
                "data": packet
            }
        
        except socket.timeout:
            return {"type": -1, "data": b"Timeout"}
        except Exception as e:
            print_error(f"Error al leer paquete: {str(e)}")
            return None
    
    def test_anonymous_access(self):
        """Probar acceso anónimo al broker MQTT"""
        print_status("Probando acceso anónimo al broker MQTT...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            # Enviar paquete CONNECT sin autenticación
            connect_packet = self.create_connect_packet()
            sock.send(connect_packet)
            
            # Leer respuesta
            response = self.read_packet(sock)
            
            if response and response["type"] == 2:  # CONNACK
                connack_rc = response["data"][1]
                
                if connack_rc == 0:
                    print_success("¡Conexión anónima aceptada! El broker permite conexiones sin autenticación")
                    
                    # Intentar suscribirse a un tema de sistema
                    subscribe_packet = self.create_subscribe_packet("$SYS/#")
                    sock.send(subscribe_packet)
                    
                    # Leer respuesta de suscripción
                    sub_response = self.read_packet(sock)
                    
                    if sub_response and sub_response["type"] == 9:  # SUBACK
                        if sub_response["data"][2] != 0x80:  # No rechazado
                            print_success("¡Suscripción anónima a temas del sistema permitida!")
                        else:
                            print_info("Suscripción anónima a temas del sistema rechazada")
                else:
                    print_info(f"Conexión anónima rechazada con código {connack_rc}")
            
            sock.close()
        
        except Exception as e:
            print_error(f"Error al probar acceso anónimo: {str(e)}")
    
    def test_auth_access(self):
        """Probar acceso con credenciales al broker MQTT"""
        if not self.username and not self.password:
            return
        
        print_status(f"Probando acceso con credenciales: {self.username}:{self.password}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            # Enviar paquete CONNECT con autenticación
            connect_packet = self.create_connect_packet(
                username=self.username,
                password=self.password
            )
            sock.send(connect_packet)
            
            # Leer respuesta
            response = self.read_packet(sock)
            
            if response and response["type"] == 2:  # CONNACK
                connack_rc = response["data"][1]
                
                if connack_rc == 0:
                    print_success(f"¡Conexión con credenciales aceptada! Usuario '{self.username}' autenticado")
                else:
                    print_info(f"Conexión con credenciales rechazada con código {connack_rc}")
            
            sock.close()
        
        except Exception as e:
            print_error(f"Error al probar acceso con credenciales: {str(e)}")
    
    def test_common_topics(self):
        """Probar suscripción a temas comunes"""
        topics_list = self.topics.split(",")
        
        if not topics_list:
            return
        
        print_status(f"Probando suscripción a {len(topics_list)} temas comunes...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            # Conectar primero (probar anónimo y luego con credenciales)
            if self.username and self.password:
                connect_packet = self.create_connect_packet(
                    username=self.username,
                    password=self.password
                )
            else:
                connect_packet = self.create_connect_packet()
            
            sock.send(connect_packet)
            
            # Leer respuesta de conexión
            response = self.read_packet(sock)
            
            if response and response["type"] == 2 and response["data"][1] == 0:
                print_info("Conexión establecida, probando temas...")
                
                accessible_topics = []
                
                for i, topic in enumerate(topics_list, 1):
                    topic = topic.strip()
                    print_status(f"Probando tema {i}/{len(topics_list)}: {topic}")
                    
                    # Enviar paquete SUBSCRIBE
                    subscribe_packet = self.create_subscribe_packet(topic, packet_id=i)
                    sock.send(subscribe_packet)
                    
                    # Leer respuesta
                    sub_response = self.read_packet(sock)
                    
                    if sub_response and sub_response["type"] == 9:  # SUBACK
                        # Revisar código de retorno
                        if len(sub_response["data"]) >= 3 and sub_response["data"][2] != 0x80:
                            print_success(f"¡Suscripción a '{topic}' aceptada!")
                            accessible_topics.append(topic)
                        else:
                            print_info(f"Suscripción a '{topic}' rechazada")
                
                if accessible_topics:
                    print_success(f"\nTemas accesibles ({len(accessible_topics)}):")
                    for topic in accessible_topics:
                        print_info(f"- {topic}")
                    
                    # Esperar un momento para recibir mensajes
                    print_status("Esperando mensajes (5 segundos)...")
                    sock.settimeout(5.0)
                    
                    try:
                        while True:
                            packet = self.read_packet(sock)
                            if packet and packet["type"] == 3:  # PUBLISH
                                topic_len = struct.unpack("!H", packet["data"][0:2])[0]
                                topic_name = packet["data"][2:2+topic_len].decode()
                                
                                # Calcular dónde empieza el payload
                                payload_start = 2 + topic_len
                                
                                # Si QoS > 0, hay un packet identifier
                                qos = (packet["type"] & 0x06) >> 1
                                if qos > 0:
                                    payload_start += 2
                                
                                payload = packet["data"][payload_start:].decode()
                                
                                print_success(f"Mensaje recibido en tema '{topic_name}':")
                                print_info(payload[:100] + ("..." if len(payload) > 100 else ""))
                    
                    except socket.timeout:
                        print_info("No se recibieron más mensajes")
                    except Exception as e:
                        print_error(f"Error al recibir mensajes: {str(e)}")
            
            else:
                print_error("No se pudo establecer conexión para probar temas")
            
            sock.close()
        
        except Exception as e:
            print_error(f"Error al probar temas comunes: {str(e)}")
