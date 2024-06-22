import win32evtlog

def analyze_created_tasks():
    logs = []

    server = 'localhost'  # Nombre del servidor
    log_types = ['Security']  # Tipo de registro
    task_creation_event_id = 4698  # ID del evento de creación de tarea

    for log_type in log_types:
        # Abre el registro de eventos
        handle = win32evtlog.OpenEventLog(server, log_type)

        # Flags para leer los eventos de forma secuencial y en orden inverso
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while True:
            # Lee los eventos del registro
            events = win32evtlog.ReadEventLog(handle, flags, 0)

            if not events:
                break
            for event in events:
                # Si el evento es una creación de tarea
                if event.EventID == task_creation_event_id:
                    # Crea un diccionario con la información del evento
                    event_info = {
                        'TaskName': event.StringInserts[4],  # El índice puede cambiar dependiendo del evento
                        'SourceName': event.SourceName,
                        'TimeGenerated': event.TimeGenerated.Format(),
                        'ComputerName': event.ComputerName
                    }
                    # Agrega el diccionario a la lista de eventos
                    logs.append(event_info)

        # Cierra el registro de eventos
        win32evtlog.CloseEventLog(handle)

    return logs
