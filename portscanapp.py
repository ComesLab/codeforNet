"associa nome applicazione ai servizi attivi sulle rispettive porte"

import subprocess
import sys
import socket
import psutil

def install_libraries():
    try:
        import nmap
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "python-nmap"])


KNOWN_APPLICATIONS = {
    "chrome.exe": "Google Chrome",
    "msedge.exe": "Microsoft Edge",
    "firefox.exe": "Mozilla Firefox",
    "explorer.exe": "File Explorer",
    "svchost.exe": "Host Servizi Windows",
    # Aggiungi altre associazioni secondo necessità
}

def scan_ports(ip, scan_type, port_range):
    import nmap
    nm = nmap.PortScanner()

    # Determina il tipo di scansione da eseguire
    scan_args = ""
    if scan_type == '1':
        scan_args = '-sS'  # Scansione SYN
        print(f"Scansione SYN per {ip}")
    elif scan_type == '2':
        scan_args = '-sA'  # Scansione ACK
        print(f"Scansione ACK per {ip}")
    elif scan_type == '3':
        scan_args = '-sU'  # Scansione UDP
        print(f"Scansione UDP per {ip}")
    else:
        print("Tipo di scansione non valido.")
        return

    # Esegui la scansione con l'intervallo di porte specificato
    print(f"Intervallo porte: {port_range}")
    nm.scan(ip, port_range, arguments=scan_args)

    # Mostra i risultati e avvia il processo sulla porta aperta
    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                state = nm[host][proto][port]['state']
                print(f"Port: {port}\tState: {state}")
                if state == 'open':
                    process_open_port(host, port)


def process_open_port(ip, port):
    try:
        # Prova a identificare il servizio sulla porta
        if port == 80 or port == 443:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)  # Timeout di connessione
                s.connect((ip, port))
                s.sendall(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip).encode())
                response = s.recv(1024)
                print(f"Risposta dalla porta {port}:\n{response.decode()}\n")

        # Identifica i processi associati alla porta
        found = False
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == port:
                pid = conn.pid
                process = psutil.Process(pid)
                process_name = process.name()
                app_name = KNOWN_APPLICATIONS.get(process_name.lower(), "Applicazione sconosciuta")
                print(f"Porta {port} aperta dal processo ID {pid} ({process_name})")
                print(f"Nome commerciale: {app_name}")
                print(f"Programma: {process.exe()}\n")
                found = True
        
        if not found:
            print(f"Nessun processo associato trovato per la porta {port}\n")

    except Exception as e:
        print(f"Errore durante l'elaborazione della porta {port}: {e}\n")


def main():
    install_libraries()
    print("Scansione Porte di un target sviluppato da Attilio Comes!")
    ip = input("Inserisci l'indirizzo IP da scansionare: ")

    # Scelta del tipo di scansione
    print("\nSeleziona il tipo di scansione:")
    print("1. Scansione SYN (-sS)")
    print("2. Scansione ACK (-sA)")
    print("3. Scansione UDP (-sU)")
    scan_type = input("Inserisci il numero corrispondente al tipo di scansione: ")

    # Scelta dell'intervallo di porte
    print("\nSeleziona l'intervallo di porte da scansionare:")
    print("1. Scansione veloce (porte comuni)")
    print("2. Scansione completa (tutte le porte)")
    print("3. Scansione personalizzata (specifica un intervallo)")
    port_mode = input("Inserisci il numero corrispondente all'intervallo: ")

    # Determina l'intervallo di porte
    port_range = ""
    if port_mode == '1':
        port_range = '20-1024'  # Porte comuni
    elif port_mode == '2':
        port_range = '1-65535'  # Tutte le porte
    elif port_mode == '3':
        start_port = input("Inserisci la porta di inizio intervallo: ")
        end_port = input("Inserisci la porta di fine intervallo: ")
        port_range = f"{start_port}-{end_port}"
    else:
        print("Modalità di intervallo non valida.")
        return

    # Avvia la scansione
    scan_ports(ip, scan_type, port_range)


if __name__ == "__main__":
    main()
