# core/ssh_manager.py
"""
Motor SSH Multi-Vendor — Powered by Netmiko.
Soporte para Cisco IOS/IOS-XE, Juniper JunOS, HP ProCurve, Huawei, MikroTik RouterOS (SSH).
"""
import logging

try:
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
    NETMIKO_AVAILABLE = True
except ImportError:
    NETMIKO_AVAILABLE = False
    logging.warning("Netmiko no disponible.")

# Tipos de dispositivo soportados por Netmiko
DEVICE_TYPES = {
    'mikrotik_routeros': {'name': 'MikroTik RouterOS (SSH)', 'default_port': 22},
    'cisco_ios':         {'name': 'Cisco IOS',                'default_port': 22},
    'cisco_xe':          {'name': 'Cisco IOS-XE',             'default_port': 22},
    'cisco_nxos':        {'name': 'Cisco NX-OS',              'default_port': 22},
    'juniper_junos':     {'name': 'Juniper JunOS',            'default_port': 22},
    'hp_procurve':       {'name': 'HP ProCurve',              'default_port': 22},
    'huawei':            {'name': 'Huawei VRP',               'default_port': 22},
    'linux':             {'name': 'Linux Server',             'default_port': 22},
    'arista_eos':        {'name': 'Arista EOS',               'default_port': 22},
    'dell_os10':         {'name': 'Dell OS10',                'default_port': 22},
}

# Comandos comunes por tipo de dispositivo
COMMAND_TEMPLATES = {
    'mikrotik_routeros': {
        'show_version':    '/system resource print',
        'show_interfaces': '/interface print',
        'show_routes':     '/ip route print',
        'show_arp':        '/ip arp print',
        'show_config':     '/export',
        'show_users':      '/user print',
        'show_firewall':   '/ip firewall filter print',
        'show_dhcp':       '/ip dhcp-server lease print',
    },
    'cisco_ios': {
        'show_version':    'show version',
        'show_interfaces': 'show ip interface brief',
        'show_routes':     'show ip route',
        'show_arp':        'show arp',
        'show_config':     'show running-config',
        'show_users':      'show users',
        'show_firewall':   'show access-lists',
        'show_dhcp':       'show ip dhcp binding',
    },
    'juniper_junos': {
        'show_version':    'show version',
        'show_interfaces': 'show interfaces terse',
        'show_routes':     'show route',
        'show_arp':        'show arp',
        'show_config':     'show configuration',
        'show_users':      'show system users',
        'show_firewall':   'show firewall counter',
        'show_dhcp':       'show dhcp server binding',
    },
}


class SSHDeviceManager:
    """Gestor de conexiones SSH multi-vendor usando Netmiko."""

    def __init__(self, host: str, username: str, password: str,
                 device_type: str = 'mikrotik_routeros', port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.device_type = device_type
        self.port = port
        self.connection = None

    def connect(self) -> tuple:
        """Establece conexión SSH. Retorna (success: bool, message: str)."""
        if not NETMIKO_AVAILABLE:
            return False, "Netmiko no está instalado."
        try:
            self.connection = ConnectHandler(
                device_type=self.device_type,
                host=self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                timeout=10,
                auth_timeout=10,
            )
            return True, f"Conexión SSH establecida con {self.host}"
        except NetmikoTimeoutException:
            return False, f"Timeout al conectar con {self.host}:{self.port}"
        except NetmikoAuthenticationException:
            return False, f"Error de autenticación en {self.host}"
        except Exception as e:
            return False, f"Error SSH: {str(e)}"

    def disconnect(self):
        """Cierra la conexión SSH."""
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.connection = None

    def execute_command(self, command: str) -> tuple:
        """Ejecuta un comando y retorna (success, output)."""
        if not self.connection:
            return False, "No conectado."
        try:
            output = self.connection.send_command(command, read_timeout=15)
            return True, output
        except Exception as e:
            return False, f"Error ejecutando comando: {str(e)}"

    def execute_template(self, template_name: str) -> tuple:
        """Ejecuta un comando pre-definido para el tipo de dispositivo."""
        templates = COMMAND_TEMPLATES.get(self.device_type, {})
        command = templates.get(template_name)
        if not command:
            return False, f"Template '{template_name}' no definido para {self.device_type}"
        return self.execute_command(command)

    def backup_config(self) -> tuple:
        """Obtiene la configuración completa del dispositivo."""
        return self.execute_template('show_config')

    def get_device_info(self) -> tuple:
        """Obtiene información del sistema."""
        return self.execute_template('show_version')


def get_supported_device_types() -> dict:
    """Retorna los tipos de dispositivo soportados."""
    return DEVICE_TYPES


def get_command_templates(device_type: str) -> dict:
    """Retorna los comandos disponibles para un tipo de dispositivo."""
    return COMMAND_TEMPLATES.get(device_type, {})


def is_netmiko_ready() -> bool:
    """Verifica si Netmiko está disponible."""
    return NETMIKO_AVAILABLE
