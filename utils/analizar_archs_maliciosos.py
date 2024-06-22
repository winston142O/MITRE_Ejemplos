from colorama import Fore
import requests
import shutil
import os

directory_to_scan = '.\\carpeta'
destination_directory = '.\\SuspiciousFiles'

def scan_file(file_path, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    params = {'apikey': api_key}
    response = requests.post(url, files=files, params=params)
    return response.json()

def get_report(resource, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': resource}
    response = requests.get(url, params=params)
    return response.json()


def print_report(file_name, report):
    print(Fore.CYAN + f"========= Reporte para {file_name} =========")
    print(Fore.YELLOW + f"Codigo Hash del archivo (SHA256): {report.get('sha256', 'N/A')}")
    print(Fore.YELLOW + f"Fecha Escaneo: {report.get('scan_date', 'N/A')}")
    print(Fore.YELLOW + f"Reportes: {report.get('positives', 'N/A')} / {report.get('total', 'N/A')}")
    print(Fore.YELLOW + "Resultados:")
    if report.get('positives', 0) > 0:
        print(Fore.RED + " - Archivo Malicioso")
    else:
        print(Fore.GREEN + " - Archivo Limpio")
    print(Fore.CYAN + "==========================================")

def copiar_archivos_sospechosos(files, destination):
    if not os.path.exists(destination):
        os.makedirs(destination)

    # Copia los archivos sospechosos al directorio de destino
    for file_info in files:
        print(Fore.CYAN + f"Copiando archivo: {file_info['name']}")
        shutil.copy(file_info['path'], destination)

    print(Fore.GREEN + "Archivos copiados con éxito.")

def scan_folder(folder_path):
    suspicious_files = []

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(Fore.CYAN + f"\n\nEscaneando archivo: {file_path}")
            scan_result = scan_file(file_path)
            resource = scan_result['resource']
            report = get_report(resource)
            print_report(file, report)

            if is_suspicious(report):
                suspicious_files.append({'path': file_path, 'name': file})

    return suspicious_files


def is_suspicious(report):
    if report.get('positives', 0) > 0:
        return True

    return False

def buscar_archivos_maliciosos(api_key):
    if not api_key:
        print("API KEY de virustotal no encontrada")
        return
    
    # Analizar los archivos
    print(Fore.CYAN + "Buscando archivos maliciosos...")
    suspicious_files = scan_folder(directory_to_scan)
    for file_info in suspicious_files:
        print(Fore.RED + f"Archivo sospechoso encontrado: {file_info['name']}")

    # Copiar archivos sospechosos al directorio de destino
    if not suspicious_files:
        print(Fore.GREEN + "No se encontraron archivos sospechosos.")
    else:
        print(Fore.RED + "\nCopiando archivos sospechosos en otro directorio...")
        copiar_archivos_sospechosos(suspicious_files, destination_directory)