from colorama import Fore
import winreg
from openai import OpenAI
from colorama import Fore, Style
import os

# Recopilacion de registros del sistema (T1119)
def find_suspicious_registry_values(hive, path):
    suspicious_values = []
    try:
        with winreg.OpenKey(hive, path) as key:
            i = 0
            while True:
                try:
                    # Enumerate values within the registry key
                    value = winreg.EnumValue(key, i)
                    value_name = value[0]
                    suspicious_values.append(f"{path}\\[{value_name}]")
                    i += 1
                except OSError:
                    break

    except Exception as e:
        print(Fore.YELLOW + f"Error abriendo las llaves: {path}, {e}")

    return suspicious_values

def analyze_with_openai(suspicious_entries: list, key: str):
    client = OpenAI(api_key=key)

    fullPrompt = ''
    for entry in suspicious_entries:
        fullPrompt += f"Registry Entry: {entry}\n"


    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{
            "role": "system",
            "content": "You have been tasked with analyzing the following registry entries for potential malicious activity. Please provide a brief analysis of each entry. Just respond with suspicious or not suspicious. EXAMPLE: 1. Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[Overwolf] - not suspicious/suspicious"
        }, {
            "role": "user",
            "content": f"Analyze the following registry entry for potential suspicious activity: {fullPrompt}"
        }],
        temperature=0.2,
        max_tokens=3072,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0,
        stream=True
    )
    analysis = ''
    backChunk = ''
    for message in response:
        if message.choices[0].delta.content != None:
            if backChunk + " " + message.choices[0].delta.content.strip().lower() == 'Not suspicious'.strip().lower():
                print(Fore.GREEN + message.choices[0].delta.content, end='')
                print(Style.RESET_ALL, end='')
            elif message.choices[0].delta.content.strip().lower().find('suspicious') != -1:
                print(Fore.RED + message.choices[0].delta.content, end='')
                print(Fore.YELLOW + " - (ALERT)", end='')
                print(Style.RESET_ALL, end='')
            else:
                print(Fore.CYAN + message.choices[0].delta.content, end='')
                print(Style.RESET_ALL, end='')
            analysis += message.choices[0].delta.content

            backChunk = message.choices[0].delta.content.strip().lower()
    return analysis

def scan_and_analyze(api_key: str) -> None:
    if not api_key:
        print("API KEY de OpenAi no encontrada...")
        return

    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services"),
        (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
        (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs"),
        (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify"),
        (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects"),
        (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"),
        (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"),
        (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"),
        (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"),
        (winreg.HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\SafeBoot\\Minimal"),
        (winreg.HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\SafeBoot\\Network"),
        (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Internet Explorer\\Main"),
        (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Internet Explorer\\Main"),
        (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup"),
        (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Startup"),
        (winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Active Setup\\Installed Components"),
        (winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Active Setup\\Installed Components")
    ]

    all_suspicious_entries = []
    for hive, path in registry_paths:
        suspicious_entries = find_suspicious_registry_values(hive, path)
        all_suspicious_entries.extend(suspicious_entries)

    analysis_results = analyze_with_openai(all_suspicious_entries, api_key)