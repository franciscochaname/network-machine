# core/telemetry/hardware.py
import logging
import re
from datetime import datetime, timedelta

class HardwareTelemetryMixin:
    def get_system_info(self):
        if not self.api: return {}
        try:
            identity = self.api.get_resource('/system/identity').get()[0].get('name', 'N/A')
            res = self.api.get_resource('/system/resource').get()[0]
            
            # 1. Temperatura y voltaje
            temp, voltage = 'N/A', 'N/A'
            try:
                health = self.api.get_resource('/system/health').get()
                if health:
                    for item in health:
                        n = str(item.get('name', '')).lower()
                        val = item.get('value', 'N/A')
                        if 'temperature' in n or 'temp' in n: temp = val
                        elif 'voltage' in n or 'volt' in n: voltage = val
                    
                    if temp == 'N/A':
                        for key in ['temperature', 'cpu-temperature', 'board-temperature']:
                            if key in health[0]: temp = health[0][key]; break
                    if voltage == 'N/A' and 'voltage' in health[0]:
                        voltage = health[0]['voltage']
            except Exception as e:
                logging.warning(f"Error en sección hardware: {e}")
                pass
            
            # 2. Uptime y Last Reboot
            uptime_str = res.get('uptime', '0s')
            last_reboot_dt = "Desconocido"
            try:
                weeks = re.search(r'(\d+)w', uptime_str)
                days = re.search(r'(\d+)d', uptime_str)
                hours = re.search(r'(\d+)h', uptime_str)
                minutes = re.search(r'(\d+)m', uptime_str)
                seconds = re.search(r'(\d+)s', uptime_str)
                
                td = timedelta(
                    weeks=int(weeks.group(1)) if weeks else 0,
                    days=int(days.group(1)) if days else 0,
                    hours=int(hours.group(1)) if hours else 0,
                    minutes=int(minutes.group(1)) if minutes else 0,
                    seconds=int(seconds.group(1)) if seconds else 0
                )
                last_reboot_dt = (datetime.now() - td).strftime("%d/%m/%Y %H:%M:%S")
            except Exception as e:
                logging.warning(f"Error en sección hardware: {e}")
                pass

            # 3. Detección de Capacidades Wireless
            has_ap = False
            try:
                wifi = self.api.get_resource('/interface/wireless').get()
                if wifi: has_ap = True
            except: pass

            return {
                "name": identity, "cpu_load": int(res.get('cpu-load', 0)),
                "free_memory": int(res.get('free-memory', 0)), "total_memory": int(res.get('total-memory', 0)),
                "uptime": uptime_str, "last_reboot": last_reboot_dt,
                "version": res.get('version', 'Desconocida'), "temperature": temp, "voltage": voltage,
                "architecture_name": res.get('architecture-name', 'N/A'),
                "board_name": res.get('board-name', 'N/A'),
                "bad_blocks": res.get('bad-blocks', '0'),
                "has_ap": has_ap
            }
        except Exception as e:
            logging.error(f"Error hardware telemetry: {e}")
            return {}

    def get_routing_health(self):
        if not self.api: return {"rutas_totales": 0, "ospf_neighbors": []}
        try:
            rutas = self.api.get_resource('/ip/route').get()
            return {
                "rutas_totales": len(rutas),
                "rutas_activas": len([r for r in rutas if r.get('active', 'false') == 'true']),
                "ospf_neighbors": []
            }
        except: return {"rutas_totales": 0, "ospf_neighbors": []}
