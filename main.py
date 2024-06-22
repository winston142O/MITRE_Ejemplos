from colorama import Fore
from utils.mitre import MitreClient
from utils.analizar_archs_maliciosos import buscar_archivos_maliciosos
from utils.claves_sospechosas import scan_and_analyze
from utils.analizar_tareas_creadas import analyze_created_tasks
from dotenv import load_dotenv
import os

load_dotenv(
    dotenv_path="api-keys.env"
)

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

def mostrar_menu():
    print("\n\n")
    print(Fore.YELLOW + "========= Menu =========")
    print(Fore.CYAN + "1. Mostrar todas las tecnicas de MITRE")
    print(Fore.CYAN + "2. Mostrar todas las subtecnicas de MITRE")
    print(Fore.CYAN + "3. Mostrar todas las mitigaciones de MITRE")
    print(Fore.CYAN + "4. Buscar una tecnica de MITRE")
    print(Fore.CYAN + "5. Buscar una subtecnica de MITRE")
    print(Fore.CYAN + "6. Buscar una mitigacion de MITRE")
    print(Fore.CYAN + "7. Analizar archivos maliciocios")
    print(Fore.CYAN + "8. Analizar tareas creadas")
    print(Fore.CYAN + "9. Buscar claves de registro sospechosas")
    print(Fore.CYAN + "10. Salir")

if __name__ == '__main__':
    cliente_mitre = MitreClient()

    while True:
        try:
            mostrar_menu()
            seleccion_menu = int(input("Opción deseada: "))
            
            match seleccion_menu:
                case 1:
                    cliente_mitre.Mostrar_todas_las_tecnicas()

                case 2:
                    cliente_mitre.Mostrar_todas_las_subtecnicas()

                case 3:
                    cliente_mitre.Mostrar_todas_las_mitigaciones()
                    
                case 4:
                    id_tec = input("Intoduzca el ID de la tecnica: ")
                    cliente_mitre.buscar_tecnica(id_tec)

                case 5:
                    id_sub = input("Intoduzca el ID de la subtecnica: ")
                    cliente_mitre.buscar_subtecnica(id_sub)
                
                case 6:
                    id_mit = input("Intoduzca el ID de la mitigacion: ")
                    cliente_mitre.buscar_mitigacion(id_mit)

                case 7:
                    buscar_archivos_maliciosos(VIRUSTOTAL_API_KEY)

                case 8:
                    print(Fore.CYAN + "\nAnalizando creación de tareas...")
                    created_tasks_logs = analyze_created_tasks()
                    for log in created_tasks_logs:
                        print(Fore.GREEN + f"Tarea creada detectada: {log['TaskName']} - {log['TimeGenerated']} - {log['ComputerName']}")

                case 9:                     
                    print(Fore.CYAN + "\nBúsqueda de claves de registro sospechosas...")
                    suspicious_registry_keys = scan_and_analyze(OPENAI_API_KEY)

                case 10:
                    break
                case _:
                    print("Opción no válida. Inténtelo de nuevo.")
        
        except ValueError:
            print("Por favor, introduzca un número válido.")