import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


def probe_host(ip, ports, timeout=0.5):
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((str(ip), port))
            s.close()

            
            if result in (0, 111, 10061):
                return True, port
        except:
            pass
    return False, None


def discover_network(network_cidr, ports, threads=100):
    network = ipaddress.ip_network(network_cidr, strict=False)
    alive_hosts = []

    print(f"[+] Ağ taranıyor: {network_cidr}\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(probe_host, ip, ports): ip
            for ip in network.hosts()
        }

        for future in as_completed(futures):
            ip = futures[future]
            alive, port = future.result()
            if alive:
                print(f"[+] Host bulundu → {ip} (port {port} cevap verdi)")
                alive_hosts.append(str(ip))

    return alive_hosts


if __name__ == "__main__":
    target_network = "192.168.1.0/24"

    
    probe_ports = [22, 80, 443, 445, 3389]

    hosts = discover_network(target_network, probe_ports)

    print(f"\nToplam tespit edilen host: {len(hosts)}")
