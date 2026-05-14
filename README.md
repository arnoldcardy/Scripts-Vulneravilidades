# Scripts-Vulneravilidades
Escaner de vulnerabilidades con el Scripts en la organizacion trabajada en el master de ciberseguridad

# Recolector de Vulnerabilidades Públicas CISA + NVD

## Descripción

Este proyecto fue desarrollado en Python con el objetivo de recopilar vulnerabilidades públicas desde fuentes oficiales de ciberseguridad y exportarlas automáticamente a un archivo Excel para fines de análisis y seguimiento.

El script consume información desde:

- CISA (Cybersecurity and Infrastructure Security Agency)
- NVD (National Vulnerability Database)

Además, enriquece los datos obteniendo:
- CVE
- CVSS
- Severidad
- Producto afectado
- Proveedor
- Descripción
- Uso conocido en campañas de ransomware

---

## Objetivo

Automatizar la recopilación de vulnerabilidades públicas y generar reportes en formato Excel que puedan ser utilizados dentro de una organización para análisis de seguridad informática y gestión de vulnerabilidades.

---

## Tecnologías Utilizadas

- Python
- Requests
- Pandas
- OpenPyXL

---

## Instalación

Instalar dependencias:

```bash
pip install requests pandas openpyxl
