from routersploit.core.exploit.printer import print_table, print_info, print_status, print_error, print_success
import os
import shutil

print_status("Aplicando mejoras de interfaz para pantallas móviles...")

# Guardar las funciones originales
original_print_table = print_table
original_print_status = print_status
original_print_info = print_info
original_print_error = print_error
original_print_success = print_success

# Determinar el ancho de la terminal
terminal_width = 80  # Valor predeterminado
try:
    terminal_width = shutil.get_terminal_size().columns
except Exception:
    pass

# Adaptar las funciones según el tamaño de la pantalla
if terminal_width < 80:
    # Modo de pantalla pequeña (móvil)
    print_info(f"Pantalla pequeña detectada ({terminal_width} columnas). Aplicando modo compacto.")
    
    def mobile_print_table(headers, *args, **kwargs):
        """Versión optimizada de print_table para pantallas pequeñas."""
        # Acortar cabeceras largas
        short_headers = []
        for header in headers:
            if isinstance(header, str) and len(header) > 10:
                short_header = header[:7] + "..."
                short_headers.append(short_header)
            else:
                short_headers.append(header)
        
        # Si hay muchas cabeceras, dividir la tabla en múltiples tablas más pequeñas
        if len(short_headers) > 3 and terminal_width < 50:
            # Mostrar en modo de lista para pantallas muy pequeñas
            print("")
            for i, header in enumerate(headers):
                print(f"\033[1m{header}:\033[0m")  # Cabecera en negrita
                
                for arg in args:
                    if i < len(arg):
                        # Formatear el valor para que quepa en la pantalla
                        value = str(arg[i])
                        if len(value) > terminal_width - 4:
                            value = value[:terminal_width - 7] + "..."
                        print(f"  {value}")
                print("")
            return
        
        # Para tablas pequeñas, usar la función original con cabeceras acortadas
        return original_print_table(short_headers, *args, **kwargs)
    
    def mobile_print_status(message):
        """Versión optimizada de print_status para pantallas pequeñas."""
        if len(message) > terminal_width - 10:
            # Dividir mensajes largos en múltiples líneas
            words = message.split()
            lines = []
            current_line = []
            
            for word in words:
                if len(" ".join(current_line + [word])) <= terminal_width - 10:
                    current_line.append(word)
                else:
                    lines.append(" ".join(current_line))
                    current_line = [word]
            
            if current_line:
                lines.append(" ".join(current_line))
            
            # Imprimir cada línea
            first_line = True
            for line in lines:
                if first_line:
                    original_print_status(line)
                    first_line = False
                else:
                    prefix = "   "  # Espacio para alinear con la primera línea
                    print(f"\033[94m{prefix}\033[0m{line}")
        else:
            return original_print_status(message)
    
    # Aplicar los parches móviles
    import routersploit.core.exploit.printer as printer
    printer.print_table = mobile_print_table
    printer.print_status = mobile_print_status

# Implementar un menú táctil simplificado que no dependa de la importación de commands
def add_touch_menu_command():
    """Agrega el comando touch_menu al intérprete sin depender de imports problemáticos"""
    try:
        # Importar el intérprete de forma segura
        from routersploit.interpreter import RoutersploitInterpreter
        
        # Definir el método para mostrar el menú táctil
        def display_touch_menu(self):
            """Muestra un menú táctil con botones grandes para acciones comunes"""
            print("\n\033[1m=== MENÚ TÁCTIL ===\033[0m")
            print("Toque para seleccionar:")
            
            # Crear botones grandes
            buttons = [
                (1, "SCAN", "use scanners/routers/router_scan"),
                (2, "SHOW", "show all"),
                (3, "BACK", "back"),
                (4, "HELP", "help"),
                (5, "EXIT", "exit"),
            ]
            
            for num, label, cmd in buttons:
                # Formatear botón para que sea más fácil tocar
                print(f"\033[1;97;44m [{num}] {label.center(8)} \033[0m : {cmd}")
            
            choice = input("\nSelección (1-5): ")
            if choice.isdigit() and 1 <= int(choice) <= 5:
                idx = int(choice) - 1
                if idx < len(buttons):
                    cmd = buttons[idx][2]
                    # Agregar comando al historial si es posible
                    if hasattr(self, 'command_history'):
                        self.command_history.append(cmd)
                    return cmd
            
            return ""
        
        # Intentar agregar el método al intérprete
        setattr(RoutersploitInterpreter, "display_touch_menu", display_touch_menu)
        
        # Agregar el comando directamente al diccionario de comandos del intérprete
        def command_touch_menu(self, *args, **kwargs):
            """Comando para mostrar el menú táctil"""
            cmd = self.display_touch_menu()
            if cmd:
                # Parsear y ejecutar el comando
                command, args, kwargs = self.parse_line(cmd)
                if command:
                    try:
                        command_handler = self.get_command_handler(command)
                        command_handler(args, **kwargs)
                    except Exception as e:
                        print_error(f"Error al ejecutar comando: {str(e)}")
        
        # Agregar el método al intérprete
        setattr(RoutersploitInterpreter, "command_touch_menu", command_touch_menu)
        
        print_success("Menú táctil habilitado. Escribe 'touch_menu' en el prompt")
        
    except Exception as e:
        print_error(f"No se pudo habilitar el menú táctil: {str(e)}")

# Intentar agregar el menú táctil
add_touch_menu_command()

print_success("Interfaz para pantallas móviles aplicada correctamente")
