import json
from base64 import urlsafe_b64encode
from typing import Any
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


def base64UrlEncode(data):
    return urlsafe_b64encode(data.encode('utf-8')).rstrip(b'=').decode("utf-8")


def base64UrlEncodeBytes(data: bytes):
    return urlsafe_b64encode(data).rstrip(b'=').decode("utf-8")


key = ECC.generate(curve='P-256')


def make_dns_challenge_txt(t_and_t):
    h = SHA256.new(t_and_t.encode('utf-8'))
    return base64UrlEncodeBytes(h.digest())


def getJWK():
    generated_key = key
    return JSON_Web_Key(
        base64UrlEncodeBytes(
            generated_key.pointQ.x.to_bytes()),  # type: ignore
        base64UrlEncodeBytes(
            generated_key.pointQ.y.to_bytes()))  # type: ignore


class JSON_Web_Key:
    '''
    A JSON object that represents a cryptographic key. The members of the object represent properties of the key, including its value.
    '''

    def __init__(self, x: str, y: str):
        self.crv: str = "P-256"  # identifies the algorithm intended for use with the key.
        self.kty: str = "EC"  # identifies the cryptographic algorithm family used with the key.
        self.x: str = x
        self.y: str = y

    def convert_to_json(self) -> str:
        content = self.__dict__
        return json.dumps(content)

    def convert_to_json_no_whitespaces(self) -> str:
        content = self.__dict__
        return json.dumps(content, separators=(',', ':'))

    def to_b64json(self) -> str:
        return base64UrlEncode(self.convert_to_json())

    def thumbprint(self):
        json_jwk = self.convert_to_json_no_whitespaces()
        h = SHA256.new(json_jwk.encode('utf-8'))
        return base64UrlEncodeBytes(h.digest())


class JSON_Payload:

    def __init__(self, content: dict[str, Any] | None = {}):
        self.payload: dict[str, Any] | None = content

    def convert_to_json(self) -> str:
        return json.dumps(self.payload)

    def to_b64json(self) -> str:
        if (self.payload is not None) or (self.payload == {}):
            return base64UrlEncode(self.convert_to_json())
        else:
            return ""


class JSON_Protected_Header:

    def __init__(
            self,
            nonce: str,  # Section 6.5
            url: str,  # Section 6.4
            jwk: JSON_Web_Key | None = None,
            kid: str | None = None):
        self.alg = "ES256"
        self.nonce: str = nonce
        self.url: str = url
        if (jwk):
            self.jwk: dict[
                str, Any] = jwk.__dict__  # jwk and kid mutually exclusive
        else:
            self.kid: str | None = kid  # will be the account url once obtained

    def convert_to_json(self) -> str:
        content = self.__dict__
        return json.dumps(content)

    def to_b64json(self) -> str:
        return base64UrlEncode(self.convert_to_json())


class JSON_Web_Signature:

    def __init__(self, protected_header: JSON_Protected_Header,
                 payload: JSON_Payload):
        message = protected_header.to_b64json() + '.' + payload.to_b64json()
        h = SHA256.new(message.encode('utf-8'))
        signer = DSS.new(key, 'fips-186-3')
        self.signature = signer.sign(h)

    def to_b64json(self) -> str:
        return base64UrlEncodeBytes(self.signature)


if __name__ == "__main__":
    pass