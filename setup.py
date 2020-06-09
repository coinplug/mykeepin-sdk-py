import setuptools
from os import path

with open("README.md", "r") as fh:
    long_description = fh.read()

loc = path.abspath(path.dirname(__file__))

with open(loc + '/requirements.txt') as f:
    requirements = f.read().splitlines()

required = []
dependency_links = []
# do not add to required lines pointing to git repositories
EGG_MARK = '#egg='
for line in requirements:
    if line.startswith('-e git:') or line.startswith('-e git+') or \
            line.startswith('git:') or line.startswith('git+'):
        if EGG_MARK in line:
            package_name = line[line.find(EGG_MARK) + len(EGG_MARK):]
            required.append(package_name)
            dependency_links.append(line)
        else:
            print('Dependency to a git repository should have the format:')
            print('git+ssh://git@github.com/xxxxx/xxxxxx#egg=package_name')
    else:
        required.append(line)

setuptools.setup(
    name="mykeepin-sdk",
    version="0.2.dev1",
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
