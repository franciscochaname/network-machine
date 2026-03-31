# core/styles.py
"""
Módulo centralizado para carga de estilos CSS.
Todos los estilos globales viven en /assets/global.css.
"""
import streamlit as st
import os

_ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'assets')


def load_global_css():
    """Carga e inyecta el archivo CSS global del sistema."""
    css_path = os.path.join(_ASSETS_DIR, 'global.css')
    with open(css_path, 'r', encoding='utf-8') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)


def hide_sidebar():
    """Oculta completamente el sidebar (usado en la pantalla de login)."""
    st.markdown(
        '<style>[data-testid="stSidebar"]{display:none !important;}</style>',
        unsafe_allow_html=True
    )
