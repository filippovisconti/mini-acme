import argparse
import json
import threading

from acme_client import ACME_Client
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from servers.cert_https_server import launch_https_server
from servers.dns_server import My_DNS_Server, craft_dns_records
from servers.shutdown_server import launch_shutdown_server
from utilities.jose import getJWK, make_dns_challenge_txt

DIR = "dir"
NEW_ACCOUNT = "sign-me-up"
NEW_NONCE = "nonce-plz"
NEW_ORDER = "order-plz"
REVOKE = "revoke-cert"


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=
        'An ACMEv2 client implementation, which also includes a Web server and a DNS server.'
    )

    parser.add_argument(
        'CHALLENGE_TYPE',
        choices=['http01', 'dns01'],
        type=str,
        help='indicates which ACME challenge type the client should perform')

    parser.add_argument(
        '--dir',
        required=True,
        type=str,
        help='the directory URL of the ACME server that should be used.')

    parser.add_argument(
        '--record',
        required=True,
        type=str,
        help=
        'the IPv4 address which must be returned by the DNS server for all A-record queries.'
    )
    parser.add_argument(
        '--domain',
        required=True,
        type=str,
        action='append',
        help=
        'the domain for  which to request the certificate. If multiple `--domain` flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., `*.example.net`.'
    )

    parser.add_argument(
        "--revoke",
        help=
        " If present, the application should immediately revoke the certificate after obtaining it",
        action="store_true")
    return parser


def main():
    '''
    Namespace(CHALLENGE_TYPE='http01', dir='www.example.com', record='1.2.3.4', domain=['www.avb.com', 'www.pippo.com'], revoke=True)
    '''
    parser = create_parser()
    arguments = parser.parse_args()
    ACME_SERVER = arguments.dir.strip("dir")
    print(ACME_SERVER)

    domains = arguments.domain
    dns_record_address = arguments.record

    client: ACME_Client = ACME_Client(server_dir=ACME_SERVER)
    try:
        dirs = client.get_request(arguments.dir)
        print(dirs.json())
    except:
        print("Error occurred")
        return

    r = client.create_order(domains=domains)

    auths = json.loads(r.text)["authorizations"]
    finalize_url = json.loads(r.text)["finalize"]

    thumbprnt = getJWK().thumbprint()

    tokens_dns: list[tuple[str, str]] = []
    tokens_http: dict[str, str] = {}
    challenge_urls_dns: list[str] = []
    challenge_urls_http: list[str] = []

    for auth in auths:
        tmp = client.post_as_get_request(auth)
        identifier = json.loads(tmp.text)["identifier"]["value"]

        for chall in json.loads(tmp.text)["challenges"]:
            token = chall["token"]
            t_and_t = token + '.' + thumbprnt

            if (chall["type"] == "dns-01"):
                tokens_dns.append(
                    (identifier, make_dns_challenge_txt(t_and_t)))
                challenge_urls_dns.append(chall["url"])

            if (chall["type"] == "http-01"):
                tokens_http.update({token: t_and_t})
                challenge_urls_http.append(chall["url"])

    client.dns_server = My_DNS_Server(
        craft_dns_records(domains=domains,
                          address=dns_record_address,
                          r_records=tokens_dns))
    client.dns_server.start_dns_server()
    res = False

    if (arguments.CHALLENGE_TYPE == "http01"):
        res = client.http_challenge(tokens_http, challenge_urls_http)

    if (arguments.CHALLENGE_TYPE == "dns01"):
        res = client.dns_challenge(urls=challenge_urls_dns)

    # if not res:
    #     print("FAILED A CHALLENGE")
    #     return None

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    key_path = "key.pem"
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    csr = client.create_certificate_signing_request(domains=domains, key=key)

    fin_response = client.finalize_challenge(finalize_url=finalize_url,
                                             cert_encoded_b64=csr)

    check_url = fin_response.headers["Location"]
    certificate_path = client.download_certificate(order_url=check_url)

    if (arguments.revoke == True):
        client.revoke_certificate(certificate_path)

    shutdown_thread = threading.Thread(target=launch_shutdown_server)
    https_server_thread = threading.Thread(target=launch_https_server,
                                           kwargs={
                                               "key_path": key_path,
                                               "certificate_path":
                                               certificate_path
                                           })

    https_server_thread.start()
    print("HTTPS server ON")
    shutdown_thread.start()
    print("Shutdown server ON")

    https_server_thread.join()
    shutdown_thread.join()


if __name__ == "__main__":
    main()
