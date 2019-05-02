OASIS CTI TC
============

The OASIS Cyber Threat Intelligence (CTI) TC (Technical Committee) was chartered to define a set of information representations and protocols to address the need to model, analyze, and share cyber threat intelligence.
In the initial phase of TC work, three specifications will be transitioned from the US Department of Homeland Security (DHS) for development and standardization under the OASIS open standards process: STIX (Structured Threat Information Expression), TAXII (Trusted Automated Exchange of Indicator Information), and CybOX (Cyber Observable Expression).

The OASIS CTI Technical Committee will:

* Define composable information sharing services for peer-to-peer, hub-and-spoke, and source subscriber threat intelligence sharing models
* Develop standardized representations for campaigns, threat actors, incidents, tactics techniques and procedures (TTPs), indicators, exploit targets, observables, and courses of action
* Develop formal models that allow organizations to develop their own standards-based sharing architectures to meet specific needs

OASIS CTI & MITRE ATT&CK
########################

On May 14th, 2018, the ATT&CK team announced that all of MITRE’s Adversarial Tactics, Techniques, and Common Knowledge content, including ATT&CK for Enterprise , PRE-ATT&CK™, and ATT&CK for Mobile, was going to be available via their own TAXII 2.0 server in STIX 2.0 format.
This move to STIX and TAXII was a great effort by the ATT&CK team to facilitate the use of the framework in a more programmatical way and allow the integration of it with several other applications. 
In order to interact with the TAXII server and handle the STIX content, MITRE created the `cti-taxii-client <https://github.com/oasis-open/cti-taxii-client>`_  and `cti-python-stix2 <https://github.com/oasis-open/cti-python-stix2>`_ libraries and released them as part of the open repositories of the OASIS Technical Committee for Cyber Threat Intelligence.

OASIS TC Open Repositories
##########################

An OASIS TC Open Repository is a public GitHub repository supporting the activities of an associated OASIS Technical Committee.
TC Open Repository contents are created through public contributions under a designated open source license, and community participants establish development priorities for assets maintained in the repository.

Repositories
************

* `cti-documentation <https://github.com/oasis-open/cti-documentation>`_: GitHub Pages site for STIX and TAXII
* `cti-marking-prototype <https://github.com/oasis-open/cti-marking-prototype>`_: Prototype for processing granular data markings in STIX
* `cti-pattern-matcher <https://github.com/oasis-open/cti-pattern-matcher>`_: Match STIX content against STIX patterns
* `cti-pattern-validator <https://github.com/oasis-open/cti-pattern-validator>`_: Validate patterns used to express Cyber Observable content in STIX Indicators
* `cti-python-stix2 <https://github.com/oasis-open/cti-python-stix2>`_: Python APIs for STIX 2
* `cti-stix-elevator <https://github.com/oasis-open/cti-stix-elevator>`_: Convert STIX 1.2 XML to STIX 2.0 JSON
* `cti-stix-slider <https://github.com/oasis-open/cti-stix-slider>`_: Convert STIX 2.0 JSON to STIX 1.2 XML
* `cti-stix-validator <https://github.com/oasis-open/cti-stix-validator>`_: Validator for STIX 2.0 JSON normative requirements and best practices
* `cti-stix-visualization <https://github.com/oasis-open/cti-stix-visualization>`_: Lightweight visualization for STIX 2.0 objects and relationships
* `cti-stix2-json-schemas <https://github.com/oasis-open/cti-stix2-json-schemas>`_: Non-normative STIX and Cyber Observable schemas and examples
* `cti-taxii-client <https://github.com/oasis-open/cti-taxii-client>`_: TAXII 2 Client Library Written in Python
* `cti-taxii-server <https://github.com/oasis-open/cti-taxii-server>`_: TAXII 2 Server Library Written in Python
* `cti-training <https://github.com/oasis-open/cti-training>`_: Collection of CTI-related training materials

References
**********

* https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cti
* https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via
* https://oasis-open.github.io/cti-documentation/resources.html#taxii-20-specification