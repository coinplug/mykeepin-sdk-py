import setuptools
from os import path

with open("README.md", "r") as fh:
    long_description = fh.read()

loc = path.abspath(path.dirname(__file__))

required = [
    "web3",
    "ecdsa",
    "requests",
    "jwcrypto"
]
dependency_links = []

setuptools.setup(
    name="mykeepin-sdk",
    version="0.2.0",
    license="LGPLv3+",
    maintainer="Coinplug, Inc.",
    maintainer_email="inyong@coinplug.com",
    url="https://github.com/coinplug/mykeepin-sdk-py",
    packages=setuptools.find_packages(),
    description="MyKeepin SDK for python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)"
    ],
    install_requires=required,
    dependency_links=dependency_links,
    python_requires='>=3.7',
)
