from setuptools import setup, find_packages

setup(
    name="evidenceshield_crypto",
    version="1.0.0",
    description="EvidenceShield AI Cryptography & Merkle Proof Engine",
    author="EvidenceShield Crypto Team",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
    ],
    entry_points={
        "console_scripts": [
            "evidenceshield-verify=evidenceshield_crypto.cli:main",
        ],
    },
)
