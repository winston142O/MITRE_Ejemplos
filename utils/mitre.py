from colorama import Fore
from mitreattack.stix20 import MitreAttackData
from typing import List


class MitreClient:
    def __init__(self):
        self.mitre_attack_data = MitreAttackData("enterprise-attack.json")
    
    def Mostrar_todas_las_tecnicas(self) -> None:
        """ Mostrar todas las técnicas registradas en la base de datos de MITRE. """

        print(Fore.CYAN + "========= Tecnicas =========")
        techniques = self.mitre_attack_data.get_techniques(remove_revoked_deprecated=True)

        for technique in techniques:
            id = self.encontrar_id_externo(technique['external_references']) 
            if id is None:
                id = technique['id']

            print(Fore.YELLOW + f"Nombre: {technique['name']}")
            print(Fore.YELLOW + f"ID: {id}")
            print(Fore.YELLOW + "---------------------------")
    
    def Mostrar_todas_las_subtecnicas(self) -> None:
        """ Mostrar todas las subtécnicas registradas en la base de datos de MITRE. """

        print(Fore.CYAN + "========= Subtecnicas =========")
        subtechniques = self.mitre_attack_data.get_subtechniques(remove_revoked_deprecated=True)

        for subtechnique in subtechniques:
            id = self.encontrar_id_externo(subtechnique['external_references']) 
            if id is None:
                id = subtechnique['id']
            
            print(Fore.YELLOW + f"Nombre: {subtechnique['name']}")
            print(Fore.YELLOW + f"ID: {id}")
            print(Fore.YELLOW + "---------------------------")

    def Mostrar_todas_las_mitigaciones(self) -> None:
        """ Mostrar mitigaciones registradas en la base de datos de MITRE. """

        print(Fore.CYAN + "========= Mitigaciones =========")
        mitigations = self.mitre_attack_data.get_mitigations(remove_revoked_deprecated=True)

        for mitigation in mitigations:
            id = self.encontrar_id_externo(mitigation['external_references']) 
            if id is None:
                id = mitigation['id']

            print(Fore.YELLOW + f"Nombre: {mitigation['name']}")
            print(Fore.YELLOW + f"ID: {id}")
            print(Fore.YELLOW + "---------------------------")

    def buscar_tecnica(self, id: str) -> None:
        """ Buscar una técnica en la base de datos de mitre mediante su ID """

        techniques = self.mitre_attack_data.get_techniques(remove_revoked_deprecated=True)
        selected = None

        for technique in techniques:
            ex_id = self.encontrar_id_externo(technique['external_references']) 
            if ex_id is None:
                ex_id = technique['id']

            if id == ex_id:
                selected = technique
                break

        if selected is None:
            print(Fore.RED + "Técnica no encontrada.")
            return

        print(Fore.CYAN + f"\n========= Técnica '{selected.name}' =========\n"
            f"\tTipo: {selected.type}\n"
            f"\tID: {selected.id}\n"
            f"\tCreada: {selected.created}\n"
            f"\tModificado: {selected.modified}\n"
            f"\tName: {selected.name}\n"
            f"\tDescripción: {selected.description}\n")
    
    def buscar_subtecnica(self, id: str) -> None:
        """ Buscar una subtécnica en la base de datos de MITRE según su ID. """

        subtechniques = self.mitre_attack_data.get_subtechniques(remove_revoked_deprecated=True)
        selected = None

        for subtechnique in subtechniques:
            ex_id = self.encontrar_id_externo(subtechnique['external_references']) 
            if ex_id is None:
                ex_id = subtechnique['id']

            if id == ex_id:
                selected = subtechnique
                break

        if selected is None:
            print(Fore.RED + "Subtécnica no encontrada.")
            return

        print(Fore.CYAN + f"\n========= Subtécnica {selected.name} =========\n"
            f"\tTipo: {selected.type}\n"
            f"\tID: {selected.id}\n"
            f"\tCreada: {selected.created}\n"
            f"\tModificado: {selected.modified}\n"
            f"\tNombre: {selected.name}\n"
            f"\ttDescripción: {selected.description}\n")
    
    def buscar_mitigacion(self, id: str) -> None: 
        """ Buscar una mitigación en la base de datos de MITRE según su ID. """

        mitigations = self.mitre_attack_data.get_mitigations(remove_revoked_deprecated=True)
        selected = None

        for mitigation in mitigations:
            ex_id = self.encontrar_id_externo(mitigation['external_references']) 
            if ex_id is None:
                ex_id = mitigation['id']

            if id == ex_id:
                selected = mitigation
                break

        if selected is None:
            print(Fore.RED + "Mitigación no encontrada.")
            return

        print(Fore.CYAN + f"\n========= Mitigación {selected.name} =========\n"
            f"\tTipo: {selected.type}\n"
            f"\tID: {selected.id}\n"
            f"\tCreada: {selected.created}\n"
            f"\tModificada: {selected.modified}\n"
            f"\tNombre: {selected.name}\n"
            f"\ttDescripción: {selected.description}\n")
    
    def encontrar_id_externo(self, referencias_externas: List[dict]) -> str:
        """ Encontrar el ID externo de un objeto (técnicas, subtécnicas, mitigaciones) en una 
            lista de referencias externas
        """

        external_id = None
        for reference in referencias_externas:
            try:
                external_id = reference['external_id']
            except Exception:
                pass
        
        return external_id
    
