.. ATTACK-Python-Client documentation master file, created by
   sphinx-quickstart on Mon Apr 29 15:40:41 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to ATTACK-Python-Client's documentation!
================================================

A Python module to access up to date ATT&CK content available in STIX format via its public TAXII server.
This project leverages the python classes and functions of the `cti-python-stix2 <https://github.com/oasis-open/cti-python-stix2>`_ and `cti-taxii-client <https://github.com/oasis-open/cti-taxii-client>`_ libraries developed by MITRE.

Goals
*****

* Provide an easy way to access and interact with up to date ATT&CK content available in STIX via public TAXII server
* Allow security analysts to quickly explore ATT&CK content and apply it in their daily operations
* Allow the integration of ATT&Ck content with other platforms to host up to date information from the framework
* Help security analysts during the transition from the ATT&CK MediaWiki API to the STIX/TAXII 2.0 API
* Learn STIX2 and TAXII Client Python libraries

.. toctree::
   :maxdepth: 2
   :caption: OASIS CTI TC

   OASIS Overview <oasis_overview>
   CTI TAXII Client <taxii_client>
   CTI STIX <stix>

.. toctree::
   :maxdepth: 2
   :caption: ATTACK CTI Library:

   Overview <attackcti_overview>

.. toctree::
   :maxdepth: 2
   :caption: Licenses:

   GNU General Public License V3 <license>