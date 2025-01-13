import nmap

def scan_ports(ip, scan_type, port_range):
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

    # Mostra i risultati
    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                state = nm[host][proto][port]['state']
                print(f"Port: {port}\tState: {state}")

def main():
    print("Scansione Porte di un target sviluppato da Attilio Comes !")
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
