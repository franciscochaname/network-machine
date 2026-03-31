# core/router_qos.py
import logging

class QoSMixin:
    def get_active_queues(self):
        """Lista todas las reglas de limitación de velocidad activas."""
        if not self.api: return []
        try:
            return self.api.get_resource('/queue/simple').get()
        except Exception as e:
            logging.error(f"Error leyendo QoS: {e}")
            return []

    def limit_bandwidth(self, target, max_mbps, comment="Limitado por SOC"):
        """
        Estrangula la velocidad. Acepta IPs (192.168.1.5), Subredes (192.168.1.0/24) 
        o Interfaces (bridge-wifi).
        """
        if not self.api: return False, "API desconectada."
        try:
            limite_bps = int(max_mbps * 1000000)
            limit_str = f"{limite_bps}/{limite_bps}"
            
            # Inteligencia de formato: Si es una IP pura sin submáscara y no es una palabra (interfaz)
            if '/' not in target and not any(c.isalpha() for c in target):
                target_final = f"{target}/32"
            else:
                target_final = target
                
            nombre_regla = f"QoS_SOC_{target_final.replace('/', '_')}"
            
            resource = self.api.get_resource('/queue/simple')
            existentes = resource.get()
            
            # Actualizar si ya existe
            for q in existentes:
                if target_final in q.get('target', ''):
                    resource.set(id=q['.id'], max_limit=limit_str, comment=comment)
                    return True, f"⚡ Velocidad de {target} actualizada a {max_mbps} Mbps."
            
            # Crear si es nueva
            resource.add(name=nombre_regla, target=target_final, max_limit=limit_str, comment=comment)
            return True, f"🚦 Tráfico del grupo {target} estrangulado a {max_mbps} Mbps."
        except Exception as e:
            return False, f"Error al limitar velocidad: {str(e)}"

    def remove_bandwidth_limit(self, target):
        """Elimina una regla de QoS existente para un objetivo."""
        if not self.api: return False, "API desconectada."
        try:
            if '/' not in target and not any(c.isalpha() for c in target):
                target_final = f"{target}/32"
            else:
                target_final = target

            resource = self.api.get_resource('/queue/simple')
            for q in resource.get():
                if target_final in q.get('target', ''):
                    resource.remove(id=q['.id'])
                    return True, f"✅ Límite de velocidad eliminado para {target}."
            return False, "No se encontró una regla activa para ese objetivo."
        except Exception as e:
            return False, f"Error al eliminar límite: {str(e)}"