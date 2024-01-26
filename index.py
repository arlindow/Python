#para instalar a biblioteca: pip install python-nmap
#para instalar o nmap tendo o chocolatey : choco install nmap
import nmap

def scan_ports(target_host):
    """
    Escaneia as portas de um host específico usando a biblioteca nmap.

    Parâmetros:
    - target_host (str): O endereço IP do host que será escaneado.

    Exemplo de Uso:
    >>> target_host = "192.168.1.1"
    >>> scan_ports(target_host)
    """

    # Cria uma instância do objeto PortScanner da biblioteca nmap
    nm = nmap.PortScanner()

    # Realiza o escaneamento de portas no host fornecido
    nm.scan(hosts=target_host, arguments='-p 1-1000')

    # Itera sobre todos os hosts escaneados
    for host in nm.all_hosts():
        print(f"Host: {host}")

        # Itera sobre os protocolos (TCP, UDP, etc.) disponíveis para cada host
        for proto in nm[host].all_protocols():
            print(f"  Protocol: {proto}")

            # Obtém as portas escaneadas para o protocolo atual
            ports = nm[host][proto].keys()

            # Itera sobre as portas escaneadas
            for port in ports:
                # Obtém o estado e o serviço associado a cada porta
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']

                # Exibe as informações da porta
                print(f"    Port: {port}\tState: {state}\tService: {service}")

if __name__ == "__main__":
    # Define o endereço IP do host alvo
    target_host = "192.168.1.1"

    # Chama a função scan_ports passando o host alvo como parâmetro
    scan_ports(target_host)





