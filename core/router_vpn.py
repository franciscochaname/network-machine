# core/router_vpn.py
class VPNMixin:
    def get_active_vpns(self):
        if not self.api: return []
        try: return self.api.get_resource('/ppp/active').get()
        except: return []

    def get_all_vpn_users(self):
        if not self.api: return False, "API desconectada."
        try: return True, self.api.get_resource('/ppp/secret').get()
        except Exception as e: return False, str(e)

    def add_vpn_user(self, name, password, service="any", profile="default-encryption", remote_address=None):
        if not self.api: return False, "API desconectada."
        try:
            params = {"name": name, "password": password, "service": service, "profile": profile}
            if remote_address: params["remote-address"] = remote_address
            self.api.get_resource('/ppp/secret').add(**params)
            return True, f"✅ Credencial para '{name}' generada."
        except Exception as e: return False, str(e)

    def delete_vpn_user(self, name):
        if not self.api: return False, "API desconectada."
        try:
            resource = self.api.get_resource('/ppp/secret')
            for u in resource.get():
                if u.get('name') == name:
                    resource.remove(id=u['.id'])
                    return True, f"🗑️ Usuario '{name}' eliminado."
            return False, "Usuario no encontrado."
        except Exception as e: return False, str(e)

    def kick_vpn_user(self, username):
        if not self.api: return False, "API desconectada."
        try:
            active = self.api.get_resource('/ppp/active')
            for u in active.get():
                if u.get('name') == username:
                    active.remove(id=u['.id'])
                    return True, f"🚨 Usuario '{username}' expulsado."
            return False, "Usuario inactivo."
        except Exception as e: return False, str(e)