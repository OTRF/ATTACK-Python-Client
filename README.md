# ATT&CK Python Client

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/OTRF/ATTACK-Python-Client/master)
[![Open_Threat_Research Community](https://img.shields.io/badge/Open_Threat_Research-Community-brightgreen.svg)](https://twitter.com/OTR_Community)
[![Open Source Love svg1](https://badges.frapsoft.com/os/v3/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)
[![Downloads](https://pepy.tech/badge/attackcti)](https://pepy.tech/project/attackcti)

A Python module to access up-to-date ATT&CK content available in [STIX](https://oasis-open.github.io/cti-documentation/stix/intro) via a public [TAXII](https://oasis-open.github.io/cti-documentation/taxii/intro) server. This project leverages python classes and functions from the [cti-python-stix2](https://github.com/oasis-open/cti-python-stix2) and [cti-taxii-client](https://github.com/oasis-open/cti-taxii-client) libraries developed by MITRE.

## Goals

* Provide an easy way to access and interact with up-to-date ATT&CK content available in STIX via public TAXII server.
* Allow security analysts to quickly explore ATT&CK content and apply it in their daily operations.
* Allow the integration of ATT&CK content with other platforms to host up to date information from the framework.
* Help security analysts during the transition from the old ATT&CK MediaWiki API to the STIX/TAXII 2.0 API.
* Learn STIX2 and TAXII Client Python libraries

## Documentation

### [https://attackcti.com](https://attackcti.com)

## Current Status: Production/Stable

The project is currently in a Production/Stable stage, which means that the current main functions are more stable. I would love to get your feedback to make it a better project.

## Resources

* [MITRE CTI](https://github.com/mitre/cti)
* [OASIS CTI TAXII Client](https://github.com/oasis-open/cti-taxii-client)
* [OASIS CTI Python STIX2](https://github.com/oasis-open/cti-python-stix2)
* [MITRE ATT&CK Framework](https://attack.mitre.org/wiki/Main_Page)
* [ATT&CK MediaWiki API](https://attack.mitre.org/wiki/Using_the_API)
* [Invoke-ATTACKAPI](https://github.com/Cyb3rWard0g/Invoke-ATTACKAPI)
* [Mitre-Attack-API](https://github.com/annamcabee/Mitre-Attack-API)

### Requirements

- Python >= 3.0
- stix2 >= 2.1.0
- taxii2-client >= 2.3.0
- six >= 1.16.0

### Installation

You can install it via pip:

```
pip install attackcti
```

Or you can also do the following:

```
git clone https://github.com/OTRF/ATTACK-Python-Client
cd ATTACK-Python-Client
pip install .
```

## Contribution

* Now that the project is more stable, It would be great to get your feedback and hopefully get more contributions to the project. Let us know if you have any features in mind. We would love to collaborate to make them happen in the project.
* Check our basic contribution guidelines and submit an issue with your ideas.
* Be concise but clear when adding a title and description to your feature proposal.
* One pull request per issue.
* Select one or more labels when you submit an issue.
* Make sure you are in the correct branch [Master].
* Try to avoid sizeable changes unless warranted.
* Be patient and polite as the project is still relatively small, which is why we would appreciate your help where possible.

## Author

* Roberto Rodriguez [@Cyb3rWard0g](https://twitter.com/Cyb3rWard0g)

## Official Committers

* Jose Luis Rodriguez [@Cyb3rPandaH](https://twitter.com/Cyb3rPandaH)
