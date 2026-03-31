# core/router_backup.py
import logging

class BackupMixin:
    """Mixin para operaciones de Backup y Disaster Recovery en MikroTik."""

    def create_router_backup(self, note=""):
        """Genera un archivo .backup binario en el almacenamiento del router."""
        if not self.api: return False, "API desconectada."
        try:
            params = {}
            if note:
                params['name'] = note
            self.api.get_resource('/system/backup').call('save', params)
            label = f"'{note}'" if note else "automático"
            return True, f"✅ Backup {label} generado exitosamente en el equipo."
        except Exception as e:
            logging.error(f"Error creando backup: {e}")
            return False, f"Error al crear backup: {str(e)}"

    def create_router_export(self):
        """Genera un archivo .rsc de texto plano (export) en el router."""
        if not self.api: return False, "API desconectada."
        try:
            self.api.get_resource('/').call('export', {'file': 'export_soc'})
            return True, "✅ Export de configuración generado como 'export_soc.rsc'."
        except Exception as e:
            logging.error(f"Error creando export: {e}")
            return False, f"Error al exportar: {str(e)}"

    def get_router_files(self):
        """Lista archivos de backup (.backup y .rsc) almacenados en el router."""
        if not self.api: return []
        try:
            files = self.api.get_resource('/file').get()
            backup_files = []
            for f in files:
                name = f.get('name', '')
                if name.endswith('.backup') or name.endswith('.rsc'):
                    # Convertir tamaño a formato legible
                    size_raw = f.get('size', '0')
                    try:
                        size_bytes = int(size_raw)
                        if size_bytes > 1048576:
                            size_fmt = f"{size_bytes / 1048576:.1f} MB"
                        elif size_bytes > 1024:
                            size_fmt = f"{size_bytes / 1024:.1f} KB"
                        else:
                            size_fmt = f"{size_bytes} B"
                    except (ValueError, TypeError):
                        size_fmt = str(size_raw)
                    
                    tipo = "🔒 Binario (.backup)" if name.endswith('.backup') else "📄 Texto (.rsc)"
                    backup_files.append({
                        'Nombre': name,
                        'Tamaño': size_fmt,
                        'Fecha': f.get('creation-time', 'N/A'),
                        'Tipo': tipo,
                        '_id': f.get('.id', ''),
                        '_name': name
                    })
            return sorted(backup_files, key=lambda x: x['Fecha'], reverse=True)
        except Exception as e:
            logging.error(f"Error leyendo archivos: {e}")
            return []

    def delete_router_file(self, file_name):
        """Elimina un archivo del almacenamiento del router por nombre."""
        if not self.api: return False, "API desconectada."
        try:
            resource = self.api.get_resource('/file')
            for f in resource.get():
                if f.get('name') == file_name:
                    resource.remove(id=f['.id'])
                    return True, f"🗑️ Archivo '{file_name}' eliminado del equipo."
            return False, "Archivo no encontrado en el equipo."
        except Exception as e:
            return False, f"Error al eliminar: {str(e)}"
