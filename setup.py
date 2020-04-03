#!/usr/bin/env python

# ATTCK TAXII Client PIP Setup script
# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: BSD 3-Clause
# Reference:
# https://packaging.python.org/tutorials/packaging-projects/

import setuptools

with open('README.md')as f:
    long_description = f.read()

setuptools.setup(
    name="attackcti",
    version="0.3.2",
    author="Roberto Rodriguez",
    description="ATTACK CTI Libary",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hunters-forge/ATTACK-Python-Client",
    keywords="threat hunting dfir cti cyber threat intelligence",
    packages=setuptools.find_packages(),
    install_requires=[
        'stix2',
        'taxii2-client',
    ],
    license='BSD',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Operating System :: OS Independent',
        'Topic :: Security',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)