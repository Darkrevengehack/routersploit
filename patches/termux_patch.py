from routersploit.core.exploit.printer import print_status, print_info, print_error
from routersploit.core.exploit.exploit import ExploitOptionsAggregator, Exploit

print_status("Parcheando RouterSploit para mejor compatibilidad con Termux...")

# ExploitOptionsAggregator es un metaclass, así que parcheamos Exploit directamente
original_run = Exploit.run

def patched_run(self):
    """
    Versión parchada del método run para mejor compatibilidad con Termux
    """
    import os
    
    # Verificar si estamos en Termux sin root
    is_termux = "com.termux" in os.environ.get("PREFIX", "")
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    
    # Verificar si el módulo podría requerir root basado en sus características
    requires_root = False
    
    # Métodos que podrían requerir root
    root_keywords = ["sniff", "mitm", "raw_socket", "scapy"]
    
    # Buscar indicadores de que el módulo podría requerir root
    for attr in dir(self):
        # Si el módulo tiene un atributo específico que indica que requiere root
        if attr == "requires_root" and getattr(self, attr):
            requires_root = True
            break
        
        # Si alguno de los métodos del módulo tiene un nombre que sugiere que requiere root
        if callable(getattr(self, attr, None)) and any(keyword in attr.lower() for keyword in root_keywords):
            requires_root = True
            break
    
    if requires_root and is_termux and not is_root:
        print_error("Este módulo podría requerir privilegios root")
        print_info("En Termux sin root, algunas funcionalidades podrían no estar disponibles")
        
        # Verificar si tenemos modo pasivo
        if hasattr(self, "passive") and self.passive:
            print_info("Modo pasivo detectado, continuando con funcionalidad limitada")
        else:
            print_info("Sugerencia: Usa el modo pasivo si está disponible")
            print_info("python rsf.py [módulo] --passive")
    
    # Ejecutar el método original
    return original_run(self)

# Aplicar el parche
Exploit.run = patched_run
print_info("Parche de compatibilidad con Termux aplicado correctamente")
