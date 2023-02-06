from dnslib import DNSRecord, textwrap, RR, A, TXT
from dnslib.server import DNSServer
from dnslib.zoneresolver import ZoneResolver

dns_port = 10053
server_address = "0.0.0.0"


def craft_dns_records(domains: list[str], address,
                      r_records):  # domain, TXT value
    result: str = ""
    for domain in domains:
        result += RR(rname=domain, rtype=1, ttl=300,
                     rdata=A(address)).toZone() + "\n"

    for domain, txt in r_records:
        result += RR(rname=f'_acme-challenge.{domain}',
                     rtype=16,
                     ttl=300,
                     rdata=TXT(txt)).toZone() + "\n"
    return result


class My_DNS_Server:

    def __init__(self, dns_zone: str):
        self.resolver = ZoneResolver(textwrap.dedent(dns_zone))
        self.dns_server = DNSServer(resolver=self.resolver,
                                    port=dns_port,
                                    address=server_address)
        self.isActive: bool = False

    def start_dns_server(self):
        if not self.isActive:
            print("Starting DNS Server")
            self.dns_server.start_thread()
            self.isActive = True

    def stop_dns_server(self):
        if self.isActive:
            print("Stopping DNS Server")
            self.dns_server.server.server_close()
            self.isActive = False
