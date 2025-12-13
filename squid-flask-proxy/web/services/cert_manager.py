import os
import subprocess


class CertManager:
    def __init__(self, ca_dir: str = "/etc/squid/ssl/certs"):
        self.ca_dir = ca_dir

    @property
    def ca_cert_path(self) -> str:
        return os.path.join(self.ca_dir, "ca.crt")

    @property
    def ca_key_path(self) -> str:
        return os.path.join(self.ca_dir, "ca.key")

    def ensure_ca(self) -> str:
        os.makedirs(self.ca_dir, exist_ok=True)
        subprocess.check_call(["/scripts/generate_ca.sh"])
        return self.ca_cert_path

    def ca_exists(self) -> bool:
        return os.path.exists(self.ca_cert_path)