import requests
import pandas as pd
from datetime import datetime
import time

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HEADERS = {
    "User-Agent": "Mozilla/5.0 Vulnerability-Collector"
}

def obtener_vulnerabilidades():

    response = requests.get(
        URL,
        headers=HEADERS,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    return data.get("vulnerabilities", [])

def obtener_cvss(cve_id):

    try:

        response = requests.get(
            NVD_URL,
            headers=HEADERS,
            params={"cveId": cve_id},
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilidades = data.get("vulnerabilities", [])

        if not vulnerabilidades:
            return "", ""

        cve = vulnerabilidades[0].get("cve", {})

        metrics = cve.get("metrics", {})

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:

            if version in metrics:

                cvss = metrics[version][0]

                score = cvss["cvssData"].get("baseScore", "")

                severity = cvss["cvssData"].get("baseSeverity", "")

                return score, severity

        return "", ""

    except requests.exceptions.HTTPError as e:

        if e.response.status_code == 429:

            print(f"[RATE LIMIT] Esperando 15 segundos...")

            time.sleep(15)

        else:

            print(f"[HTTP ERROR] {cve_id}: {e}")

        return "", ""

    except Exception as e:

        print(f"[ERROR] {cve_id}: {e}")

        return "", ""

def generar_excel(vulnerabilidades):

    registros = []

    total_original = len(vulnerabilidades)

    # Escaner 300 Vulnerabilidades
    vulnerabilidades = vulnerabilidades[:300]

    total = len(vulnerabilidades)

    print(f"\nProcesando {total} vulnerabilidades...\n")

    for i, vuln in enumerate(vulnerabilidades, start=1):

        cve_id = vuln.get("cveID", "")

        print(f"[{i}/{total}] Procesando {cve_id}...")

        cvss, severidad = obtener_cvss(cve_id)

        registros.append({

            "CVE": cve_id,
            "Proveedor": vuln.get("vendorProject", ""),
            "Producto": vuln.get("product", ""),
            "Vulnerabilidad": vuln.get("vulnerabilityName", ""),
            "Fecha": vuln.get("dateAdded", ""),
            "Descripción": vuln.get("shortDescription", ""),
            "Acción requerida": vuln.get("requiredAction", ""),
            "CVSS": cvss,
            "Severidad": severidad,
            "Ransomware": vuln.get("knownRansomwareCampaignUse", "")

        })

        # PAUSA PARA EVITAR BLOQUEOS
        time.sleep(1)

    df = pd.DataFrame(registros)

    archivo = f"vulnerabilidades_cisa_cvss_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

    df.to_excel(archivo, index=False)

    print("\n===================================")
    print("Excel generado correctamente")
    print(f"Archivo: {archivo}")
    print(f"Total procesadas: {len(df)}")
    print(f"Total disponibles en CISA: {total_original}")
    print("===================================")

def main():

    inicio = datetime.now()

    print("===================================")
    print("RECOLECTOR DE VULNERABILIDADES CISA + NVD")
    print("===================================\n")

    vulnerabilidades = obtener_vulnerabilidades()

    print(f"Total encontradas: {len(vulnerabilidades)}")

    generar_excel(vulnerabilidades)

    fin = datetime.now()

    duracion = fin - inicio

    print(f"\nTiempo total: {duracion}")

if __name__ == "__main__":

    main()