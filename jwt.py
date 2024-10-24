import json
import base64
from typing import Tuple
from cryptography.hazmat.primitives.hmac import hashes, HMAC


def base64_url_encode(arg: bytes) -> str:
    """
        Implement a Base64 encoding function without
        padding (based on RFC 7515 Appendix C).
    """

    s = base64.urlsafe_b64encode(arg).decode('utf-8')
    s = s.split('=')[0]

    return s


def base64_url_decode(arg: str) -> bytes:
    """
        Implement a Base64 decoding function which adds
        padding if necessary (based on RFc 7515 Appendix C).
    """
    if len(arg) % 4 == 2:
        arg += "=="
    elif len(arg) % 4 == 3:
        arg += "="

    return base64.urlsafe_b64decode(arg)


def get_jwt_components(jwt: str) -> Tuple[str, str, str]:
    """
        Decompose a JWT into its constituent components
        (header, payload, signature), returning a tuple
        of the same, in that order.
    """
    jwt_components = jwt.split('.')

    # header, payload, signature
    return jwt_components[0], jwt_components[1], jwt_components[2]


def get_signature(key: bytes, hash_func: hashes, header: str,
                  payload: str) -> str:
    """
        Compute a HMAC digest (as a base64 UTF-8 string) using key
        and base64 UTF-8 representations of header and payload.

        Return value is a base64 UTF-8 encoded HMAC digest.
    """

    hmac_func = HMAC(
        key=key,
        algorithm=hash_func()
    )

    # Assume header and payload are already base64, UTF-8
    hmac_func.update(bytes(f"{header}.{payload}", 'utf-8'))

    try:
        return base64_url_encode(hmac_func.finalize())
    except Exception as e:
        print(f"Signature generation failed: {e}")
        raise e


def jwt_verify(key: bytes, hash_func: hashes, jwt: str) -> None:
    """
        Verify if a JWT (UTF-8 string) has a valid signature.
        Raise an exception the signature and the digest do not match.
    """

    # Decompose JWT into header, payload, signature
    header, payload, signature = get_jwt_components(jwt)    # UTF-8 Base64

    try:
        hmac_func = HMAC(
            key=key,
            algorithm=hash_func()
        )
        hmac_func.update(bytes(f"{header}.{payload}", 'utf-8'))

        # Decode from Base64 str => bytes object
        signature_bytes = base64_url_decode(signature)
        hmac_func.verify(signature_bytes)
    except Exception as e:
        print(f"Error encountered: {e}")
        raise e


def jwt_encode(key: bytes, hash_func: hashes, header: dict,
               payload: dict) -> str:
    header_b64 = base64_url_encode(bytes(json.dumps(header), 'utf-8'))
    payload_b64 = base64_url_encode(bytes(json.dumps(payload), 'utf-8'))

    signature = get_signature(
        key=key,
        hash_func=hash_func,
        header=header_b64,
        payload=payload_b64
    )

    return "{}.{}.{}".format(header_b64, payload_b64, signature)


def jwt_decode(jwt_str: str) -> Tuple[dict, dict]:
    """
        Given a UTF-8 encoded JWT string, base64-decode its header and payload
        components, returning a tuple of dictionaries from the decoded JSON.
    """
    jwt = get_jwt_components(jwt_str)
    header, payload = jwt[0], jwt[1]

    header_bytes = base64_url_decode(header)
    decoded_header = json.loads(header_bytes.decode('utf-8'))

    payload_bytes = base64_url_decode(payload)
    decoded_payload = json.loads(payload_bytes.decode('utf-8'))

    return decoded_header, decoded_payload


def jwt_decode_verify(key: bytes, hash_func: hashes,
                      jwt_str: str) -> Tuple[dict, dict]:
    """
        If the signature matches the digest, decode jwt_str and return
        dictionaries corresponding to header and payload. Otherwise,
        raise an error.
    """
    try:
        jwt_verify(
            key=key,
            hash_func=hash_func,
            jwt=jwt_str
        )
    except Exception as e:
        raise e

    decoded_header, decoded_payload = jwt_decode(jwt_str)
    return decoded_header, decoded_payload
