
# Performance Optimization for RouterSploit
# Mejora el rendimiento en dispositivos móviles

import os
import sys
import gc
import threading
import time

# Optimizaciones de memoria
def optimize_memory():
    # Forzar recolección de basura para liberar memoria
    gc.collect()
    
    # Establecer umbrales más agresivos para GC en dispositivos con poca memoria
    gc.set_threshold(100, 5, 5)  # Valores predeterminados: 700, 10, 10

# Limitar el número de hilos para evitar sobrecargar dispositivos móviles
def limit_threads():
    original_thread_init = threading.Thread.__init__
    
    def limited_thread_init(self, *args, **kwargs):
        # Limitar el número de hilos activos
        while threading.active_count() > 20:  # Máximo 20 hilos simultáneos
            time.sleep(0.1)
        
        original_thread_init(self, *args, **kwargs)
    
    threading.Thread.__init__ = limited_thread_init

# Optimizar tiempo de espera para conexiones
def optimize_timeouts():
    from routersploit.core.tcp.tcp_client import TCPClient
    
    # Almacenar método original
    original_connect = TCPClient.connect
    
    # Crear versión optimizada
    def optimized_connect(self):
        # Reducir tiempo de espera para conexiones en dispositivos móviles
        self.peer.settimeout(3)  # Valor predeterminado: 10
        return original_connect(self)
    
    # Reemplazar método
    TCPClient.connect = optimized_connect

# Iniciar optimizaciones
def start_optimizations():
    optimize_memory()
    limit_threads()
    
    # Solo modificar timeouts si se está ejecutando RouterSploit
    if "rsf.py" in sys.argv[0] or "routersploit" in sys.argv[0]:
        optimize_timeouts()
    
    # Configurar variables de entorno para optimizar Python
    os.environ["PYTHONUNBUFFERED"] = "1"  # Deshabilitar buffer para E/S
    
    # Establecer pila recursiva más pequeña para ahorrar memoria
    sys.setrecursionlimit(1000)  # Valor predeterminado: 1000
    
    # Notificar que las optimizaciones están activas
    if os.environ.get("RSF_VERBOSE", "0") == "1":
        print("[*] Performance optimizations loaded")

# Iniciar optimizaciones si este archivo se importa directamente
start_optimizations()
