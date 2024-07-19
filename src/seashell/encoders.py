import base64
import urllib
import urllib.parse
from abc import ABC, abstractmethod


class RecursiveEncoder(ABC):
    """Abstract base class for an encoder supporting multiple iterations"""

    def encode(self, data: bytes, iterations: int) -> bytes:
        """Wraps the transform method while adding support for multiple iterations

        Parameters
        ----------
        data : bytes
            Data to be encoded
        iterations : int
            The number of times to encode the payload

        Returns
        -------
        bytes
            _description_
        """
        for _ in range(iterations):
            data = self.transform(data)

        return data

    @abstractmethod
    def transform(self, data: bytes) -> bytes: ...

    """
    Abstract method for the actual encoding process

    Returns
    -------
    bytes
        The encoded bytes
    """


class B64RecursiveEncoder(RecursiveEncoder):
    def transform(self, data: bytes) -> bytes:
        return base64.b64encode(data)


class URLRecursiveEncoder(RecursiveEncoder):
    def transform(self, data: bytes) -> bytes:
        return urllib.parse.quote_from_bytes(data).encode()


ENCODER_MAP = {"base64": B64RecursiveEncoder, "url": URLRecursiveEncoder}
