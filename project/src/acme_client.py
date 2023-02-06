import json, requests
from time import sleep
import threading
from pathlib import Path

from servers.challenge_http_server import launch_challenge_server
from servers.dns_server import My_DNS_Server
from utilities.jose import (JSON_Payload, JSON_Protected_Header, JSON_Web_Key,
                            JSON_Web_Signature, getJWK, base64UrlEncodeBytes)

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

NEW_ACCOUNT = "sign-me-up"
NEW_NONCE = "nonce-plz"
NEW_ORDER = "order-plz"
REVOKE = "revoke-cert"


class ACME_Client:

    def __init__(self, server_dir) -> None:
        self.server_dir: str = server_dir
        self.session: requests.Session = requests.Session()
        self.issued_nonces: list[str] = []
        self.kid: str | None = None  # will contain account URL
        self.dns_server: My_DNS_Server = None  # type: ignore

    def get_nonce(self):
        if not (self.issued_nonces):

            response = self.head_request(self.server_dir + NEW_NONCE)
            if "Replay-Nonce" in response.headers:
                self.issued_nonces.append(response.headers["Replay-Nonce"])

        return self.issued_nonces.pop()

    def head_request(self, url: str):
        return self.session.head(url, verify="../pebble.minica.pem")

    def get_request(self, url: str) -> requests.Response:
        return self.session.get(url, verify="../pebble.minica.pem")

    def _internal_post(self, url: str, JSONheader64: str, JSONpayload64: str,
                       JSONsignature64: str) -> requests.Response:
        request_header = {"Content-Type": "application/jose+json"}
        # print("post request details")
        # print(
        #     json.dumps({
        #         "protected": f"{JSONheader64}",
        #         "payload": f"{JSONpayload64}",
        #         "signature": f"{JSONsignature64}",
        #     }))
        response = self.session.post(url=url,
                                     data=json.dumps({
                                         "protected":
                                         f"{JSONheader64}",
                                         "payload":
                                         f"{JSONpayload64}",
                                         "signature":
                                         f"{JSONsignature64}",
                                     }),
                                     headers=request_header,
                                     verify="../pebble.minica.pem")

        if "Replay-Nonce" in response.headers:
            self.issued_nonces.append(response.headers["Replay-Nonce"])
        return response

    def post_request(self, url: str, protected_header: JSON_Protected_Header,
                     payload: JSON_Payload) -> requests.Response:

        signature: JSON_Web_Signature = JSON_Web_Signature(
            protected_header=protected_header, payload=payload)

        return self._internal_post(url, protected_header.to_b64json(),
                                   payload.to_b64json(),
                                   signature.to_b64json())

    def post_as_get_request(self, url: str) -> requests.Response:
        '''     
        If a client wishes to fetch a resource from the server (which would
        otherwise be done with a GET), then it MUST send a POST request with
        a JWS body as described above, where the payload of the JWS is a
        zero-length octet string.  In other words, the "payload" field of the
        JWS object MUST be present and set to the empty string ("").
        '''

        prot_head: JSON_Protected_Header = JSON_Protected_Header(
            self.get_nonce(), url, kid=self.kid)

        json_payload: JSON_Payload = JSON_Payload(None)

        signature: JSON_Web_Signature = JSON_Web_Signature(
            protected_header=prot_head, payload=json_payload)

        return self._internal_post(url, prot_head.to_b64json(),
                                   json_payload.to_b64json(),
                                   signature.to_b64json())

    def create_account(self):
        if self.kid != None:
            print("NB: Account already exists.")
        payload = {"termsOfServiceAgreed": True}
        req_url = self.server_dir + NEW_ACCOUNT
        jwk: JSON_Web_Key = getJWK()
        # print("# printing JWK")
        # print(jwk)
        prot_head: JSON_Protected_Header = JSON_Protected_Header(
            self.get_nonce(), req_url, jwk=jwk)

        json_payload: JSON_Payload = JSON_Payload(payload)

        response: requests.Response = self.post_request(
            req_url, prot_head, json_payload)
        # print(response.text)
        if "Location" in response.headers:
            self.kid = response.headers["Location"]
            # print("Account Url: " + self.kid)
            self.jwk = None

        return self.kid

    def create_order(self, domains: list[str]):
        if self.kid == None:
            self.create_account()
        ids = []
        for domain in domains:
            ids.append({"type": "dns", "value": f"{domain}"})
        payload = {"identifiers": ids}

        req_url = self.server_dir + NEW_ORDER
        prot_head: JSON_Protected_Header = JSON_Protected_Header(
            self.get_nonce(), req_url, kid=self.kid)

        json_payload: JSON_Payload = JSON_Payload(payload)

        response: requests.Response = self.post_request(
            req_url, prot_head, json_payload)

        return response

    def http_challenge(self, tokens: dict[str, str], urls: list[str]):

        # print("Received tokens: ")
        # print(tokens)

        challenge_server_thread = threading.Thread(
            target=launch_challenge_server, args=([tokens]))
        challenge_server_thread.start()

        # print("started, wait 3 seconds")
        sleep(3)
        # print("finished waiting")
        for url in urls:
            print(self.challenge_ready(url).text)
            print("HTTP Challenge ready for " + url)

        return self.check_challenge("http-01", urls)

    def challenge_ready(self, url):
        return self.post_request(url=url,
                                 protected_header=JSON_Protected_Header(
                                     nonce=self.get_nonce(),
                                     url=url,
                                     kid=self.kid),
                                 payload=JSON_Payload())  # Payload {}, not ""

    def check_challenge(self, type, urls):
        res = True
        for url in urls:
            print(f"{type} Waiting for " + url)

            while True:
                print("Wait... ")
                response = json.loads(self.post_as_get_request(url).text)

                status = response["status"]
                # print(f"Current Status: {status}")
                # print(f"Current response: {response}")
                if (status == "valid"):
                    print(f"\n\nSUCCESS {type}! Final Status: {status}")
                    print("\nDone {type} for " + url)
                    break
                if (status == "invalid"):
                    print(f"\n\nFAILED {type}! Final Status: {status}")
                    print(f"Final response: {response}")
                    print("\nDone {type} for " + url)
                    res = False
                    break
                sleep(8)
        return res

    def dns_challenge(
            self,  #domain_and_tokens: list[tuple[str, str]],
            urls: list[str]):
        # print("Received tokens: ")
        # print(tokens)

        for url in urls:
            r = self.challenge_ready(url).text
            # print(r)
            print("DNS Challenge ready for " + url)

        return self.check_challenge("dns-01", urls)

    def download_certificate(self, order_url):
        while True:
            sleep(5)
            res = self.post_as_get_request(url=order_url)
            print("DOWNLOAD: " + res.text)

            if json.loads(res.text)["status"] == "valid":
                download_cert_url = json.loads(res.text)["certificate"]
                cert = self.post_as_get_request(download_cert_url).content

                certificate_path = "cert.pem"
                with open(certificate_path, "wb") as f:
                    f.write(cert)
                return certificate_path

    def revoke_certificate(self, certificate_path: str):
        print("Revoking certificate")
        certificate = x509.load_pem_x509_certificate(open(
            certificate_path, "rb").read(),
                                                     backend=default_backend())
        result = self.post_request(
            url=self.server_dir + REVOKE,
            protected_header=JSON_Protected_Header(nonce=self.get_nonce(),
                                                   url=(self.server_dir +
                                                        REVOKE),
                                                   kid=self.kid),
            payload=JSON_Payload(
                content={
                    "certificate":
                    base64UrlEncodeBytes(
                        certificate.public_bytes(serialization.Encoding.DER))
                }))
        print(result.status_code)
        print(result.headers)
        return result

    def create_certificate_signing_request(self, domains: list[str],
                                           key) -> str:
        '''
        Returns a csr encoded in base64
        '''
        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                # Provide various details about who we are.
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,
                                   "Switzerland"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Zurich"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                   "Filippovisconti")
            ])).add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(domain) for domain in domains]),
                critical=False,
                # Sign the CSR with our private key.
            ).sign(key, hashes.SHA256(), backend=default_backend())

        return base64UrlEncodeBytes(
            csr.public_bytes(serialization.Encoding.DER))

    def finalize_challenge(self, finalize_url, cert_encoded_b64):
        return self.post_request(
            url=finalize_url,
            protected_header=JSON_Protected_Header(self.get_nonce(),
                                                   finalize_url,
                                                   kid=self.kid),
            payload=JSON_Payload({"csr": f"{cert_encoded_b64}"}))


if __name__ == "__main__":
    pass
