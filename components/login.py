import streamlit as st
import time
from core.security import verify_password
from core.styles import hide_sidebar
from database.db_models import SessionLocal, User, AuditLog

def render_login(cookies):
    hide_sidebar()

    # Layout centrado con dos columnas (Imagen | Formulario)
    st.markdown("<div style='height: 10vh;'></div>", unsafe_allow_html=True)
    c_left, c_main, c_right = st.columns([1, 4, 1])
    
    with c_main:
        st.markdown('<div class="login-wrapper-light">', unsafe_allow_html=True)
        col_img, col_form = st.columns([1.2, 1])
        
        with col_img:
            import os
            _login_img = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'assets', 'login_bg.png')
            if os.path.exists(_login_img):
                st.image(_login_img, use_container_width=True)
            else:
                st.markdown("""
                <div style="background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 40%, #3b82f6 100%); height: 400px; border-radius: 20px 0 0 20px; display: flex; flex-direction: column; align-items: center; justify-content: center; color: white; gap: 10px;">
                    <div style="font-size: 4em;">🌐</div>
                    <h2 style="margin: 0; font-weight: 700; letter-spacing: 2px;">NOC Engine</h2>
                    <p style="color: rgba(255,255,255,0.6); font-size: 0.85em;">Network Operations Center</p>
                </div>
                """, unsafe_allow_html=True)
                
        with col_form:
            st.markdown("""
            <div class="login-card-light">
                <div class="login-title-light">NetOps Center</div>
                <div class="login-subtitle-light" style="margin-bottom: 2rem;">Security Operations Console</div>
            """, unsafe_allow_html=True)

            with st.form("login_form"):
                st.markdown("##### Acceso al Sistema")
                username = st.text_input("Usuario", placeholder="admin")
                password = st.text_input("Contraseña", type="password", placeholder="••••••••")

                submit = st.form_submit_button("Iniciar Sesión", use_container_width=True, type="primary")

                if submit:
                    # Form Validation Check
                    if not username or not password:
                        st.error("⚠️ Ambos campos son obligatorios.")
                    else:
                        db = SessionLocal()
                        user = db.query(User).filter(User.username == username).first()
                        db.close()
                        if user and user.is_active and verify_password(password, user.password_hash):
                            cookies.set("is_logged_in", True)
                            cookies.set("username", user.username)
                            cookies.set("role", user.role)
                            st.session_state['logged_in'] = True
                            st.session_state['username'] = user.username
                            st.session_state['role'] = user.role
                            st.rerun()
                        else:
                            st.error("🚫 Credenciales incorrectas o usuario inactivo. Contacta al administrador del SOC.")

            st.markdown("""
                <div style="margin-top: 2rem; font-size: 0.8rem; color: #64748b; text-align: center;">
                    Sistema Autorizado Únicamente v4.0
                </div>
            </div>
            </div>
            """, unsafe_allow_html=True)
    
    st.stop()
