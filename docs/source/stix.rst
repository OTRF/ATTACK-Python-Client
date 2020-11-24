CTI Python STIX
===============

The cti-python-stix2 library was developed by MITRE to help users serialize/de-serialize, produce, consume, and process STIX 2 content.

What is STIX?
#############

Structured Threat Information Expression (STIX™) is a language and serialization format used to exchange cyber threat intelligence (CTI).

STIX Objects
############

STIX Objects categorize each piece of information with specific attributes to be populated.
Chaining multiple objects together through relationships allow for easy or complex representations of CTI.

* **Attack Pattern**: A type of Tactics, Techniques, and Procedures (TTP) that describes ways threat actors attempt to compromise targets.
* **Campaign**: A grouping of adversarial behaviors that describes a set of malicious activities or attacks that occur over a period of time against a specific set of targets.
* **Course of Action**: An action taken to either prevent an attack or respond to an attack.
* **Identity**: Individuals, organizations, or groups, as well as classes of individuals, organizations, or groups.
* **Indicator**: Contains a pattern that can be used to detect suspicious or malicious cyber activity.
* **Intrusion Set**: A grouped set of adversarial behaviors and resources with common properties believed to be orchestrated by a single threat actor.
* **Malware**: A type of TTP, also known as malicious code and malicious software, used to compromise the confidentiality, integrity, or availability of a victim’s data or system.
* **Observed Data**: Conveys information observed on a system or network (e.g., an IP address).
* **Report**: Collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including contextual details.
* **Threat Actor**: Individuals, groups, or organizations believed to be operating with malicious intent.
* **Tool**: Legitimate software that can be used by threat actors to perform attacks.
* **Vulnerability**: A mistake in software that can be directly used by a hacker to gain access to a system or network.

STIX also defines two relationship objects (SROs)

* Relationship: Used to link two SDOs and to describe how they are related to each other.
* Sighting: Denotes the belief that an element of CTI was seen (e.g., indicator, malware).

STIX & ATT&CK
#############

The ATT&CK framework is now available on a public TAXII server, and the content is in STIX2 format.
Therefore, the ATT&Ck team had to map/translate ATT&CK objects and properties to STIX 2.0 objects and properties syntax.

+---------------+-------------------+
|ATT&CK Concept | STIX Object Type  |
+===============+===================+
| Technique     | attack-pattern    | 
+---------------+-------------------+
| Group         | intrusion-set     |
+---------------+-------------------+
| Software      | malware or tool   |
+---------------+-------------------+
| Mitigation    | course-of-action  |
+---------------+-------------------+
| Tactic        | x-mitre-tractic   |
+---------------+-------------------+
| Matrix        | x-mitre-matrix    |
+---------------+-------------------+

You can learn more about the mapping concepts `here <https://github.com/mitre/cti/blob/master/USAGE.md#mapping-concepts>`_.

Even though ATT&CK content can be retrieved from its public TAXII server via its own taxii client python library, the cti-taxii-client was developed to consume and process the STIX content in a more efficient way.
The ``get_object`` method from the TAXII client library works well if you already have a specific id of a STIX object.
However, the cti-python-stix2 library provides a more dynamic and flexible filtering capability to retrieve ATT&CK content by specific STIX objects such as ``attack-patterns``, ``intrusion-set``, ``x-mitre-matrix``, etc.

ATT&CK users can use the cti-python-stix2 library to retrieve STIX 2.0 data, but they must first reference a STIX ``Data Source``.

* Data Sources represent locations from which STIX data can be retrieved.
* The STIX library comes with a TAXIICollection suite that contains TAXIICollectionStore, TAXIICollectionSource, and TAXIICollectionSink classes.
* The TAXIICollection suite supports searching on all STIX2 common object properties. This works simply by augmenting the filtering that is done remotely at the TAXII2 server instance.
* The TAXIICollection will seperate any supplied queries into TAXII supported filters and non-supported filters.
* During a TAXIICollection API call, TAXII2 supported filters get inserted into the TAXII2 server request (to be evaluated at the server). The rest of the filters are kept locally and then applied to the STIX2 content that is returned from the TAXII2 server, before being returned from the TAXIICollection API call.
* The TAXIICollectionSource class retrieves STIX content from local/remote TAXII Collection(s)
* The TAXIICollectionSource class can be used with a ``Collection`` object that can be instantiated by the taxii client library.

Query ATT&CK
############

ATT&CK users can use the taxii client and stix libraries together to reference specific STIX objects available in the public ATT&CK TAXII server:

.. code-block:: python

    >>> from stix2 import TAXIICollectionSource, Filter
    >>> from taxii2client.v20 import Collection

    >>> ATTCK_STIX_COLLECTIONS = "https://cti-taxii.mitre.org/stix/collections/"
    >>> ENTERPRISE_ATTCK = "95ecc380-afe9-11e4-9b6c-751b66dd541e"
    >>> PRE_ATTCK = "062767bd-02d2-4b72-84ba-56caef0f8658"
    >>> MOBILE_ATTCK = "2f669986-b40b-4423-b720-4396ca6a462b"

    >>> ENTERPRISE_COLLECTION = Collection(ATTCK_STIX_COLLECTIONS + ENTERPRISE_ATTCK + "/")
    >>> TC_ENTERPRISE_SOURCE = TAXIICollectionSource(ENTERPRISE_COLLECTION)

    >>> PRE_COLLECTION = Collection(ATTCK_STIX_COLLECTIONS + PRE_ATTCK + "/")
    >>> TC_PRE_SOURCE = TAXIICollectionSource(PRE_COLLECTION)

    >>> MOBILE_COLLECTION = Collection(ATTCK_STIX_COLLECTIONS + MOBILE_ATTCK + "/")
    >>> TC_MOBILE_SOURCE = TAXIICollectionSource(MOBILE_COLLECTION)

We can then use the ``Filter`` class available in STIX to retrieve multiple objects:

.. code-block:: python

    >>> enterprise_stix_objects = {}
    >>> enterprise_filter_objects = {
    ... "techniques": Filter("type", "=", "attack-pattern"),
    ... "mitigations": Filter("type", "=", "course-of-action"),
    ... "groups": Filter("type", "=", "intrusion-set"),
    ... "malware": Filter("type", "=", "malware"),
    ... "tools": Filter("type", "=", "tool"),
    ... "relationships": Filter("type", "=", "relationship")
    ... }

    >>> for key in enterprise_filter_objects:
    ...     enterprise_stix_objects[key] = self.TC_ENTERPRISE_SOURCE.query(enterprise_filter_objects[key])

You can learn more about **Filters** `here <https://stix2.readthedocs.io/en/latest/api/datastore/stix2.datastore.filters.html>`_.

We can now display the first element in the list of ``techniques`` of the ``enterprise_stix_objects`` dictionary and validate that we were able to retrieve data from ATT&CK public TAXII server:

.. code-block:: python

    >>> enterprise_stix_objects["techniques"][0]
    AttackPattern(
        type='attack-pattern',
        id='attack-pattern--cf7b3a06-8b42-4c33-bbe9-012120027925',
        created_by_ref='identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5',
        created='2019-04-25T20:53:07.719Z',
        modified='2019-04-29T21:13:49.686Z',
        name='Compile After Delivery',
        description='Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Similar to [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027),
        text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution; typically via native utilities such as csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)\n\nSource code payloads may also be encrypted, encoded, and/or embedded within other files, such as those delivered as a [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193).
        Payloads may also be delivered in formats unrecognizable and inherently benign to the native OS (ex: EXEs on macOS/Linux) before later being (re)compiled into a proper executable binary with a bundled compiler and execution framework.(Citation: TrendMicro WindowsAppMac)\n',
        kill_chain_phases=[KillChainPhase(kill_chain_name='mitre-attack', phase_name='defense-evasion')],
        external_references=[
            ExternalReference(
                source_name='mitre-attack',
                url='https://attack.mitre.org/techniques/T1500',
                external_id='T1500'
            ),
            ExternalReference(
                source_name='ClearSky MuddyWater Nov 2018',
                description='ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.',
                url='https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf'
            ),
            ExternalReference(
                source_name='TrendMicro WindowsAppMac',
                description='Trend Micro. (2019, February 11). Windows App Runs on Mac, Downloads Info Stealer and Adware. Retrieved April 25, 2019.',
                url='https://blog.trendmicro.com/trendlabs-security-intelligence/windows-app-runs-on-mac-downloads-info-stealer-and-adware/'
            )
        ],
        object_marking_refs=['marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'],
        x_mitre_contributors=['Ye Yint Min Thu Htut, Offensive Security Team, DBS Bank', 'Praetorian'],
        x_mitre_data_sources=['Process command-line parameters', 'Process monitoring', 'File monitoring'],
        x_mitre_defense_bypassed=['Static File Analysis', 'Binary Analysis', 'Anti-virus', 'Host intrusion prevention systems', 'Signature-based detection'],
        x_mitre_detection='Monitor the execution file paths and command-line arguments for common compilers, such as csc.exe and GCC/MinGW, and correlate with other suspicious behavior to reduce false positives from normal user and administrator behavior. The compilation of payloads may also generate file creation and/or file write events. Look for non-native binary formats and cross-platform compiler and execution frameworks like Mono and determine if they have a legitimate purpose on the system.(Citation: TrendMicro WindowsAppMac) Typically these should only be used in specific and limited cases, like for software development.',
        x_mitre_permissions_required=['User'],
        x_mitre_platforms=['Linux', 'macOS', 'Windows'],
        x_mitre_system_requirements=['Compiler software (either native to the system or delivered by the adversary)'],
        x_mitre_version='1.0'
    )

You can also retrieve all the stix objects available for each collection without providing a filter:

.. code-block:: python

    >>> enterprise_objects = TC_ENTERPRISE_SOURCE.query()
    >>> type(enterprise_objects)
    <class 'list'>

You can then use a similar ``for`` loop and an empty list to capture all the STIX object types and count the number of records per object type:

.. code-block:: python

    >>> enterprise_list = []
    >>> for o in enterprise_objects:
    ...     enterprise_list.append[o['type']]

    >>> from collections import Counter
    >>> Counter(enterprise_list)
    Counter({
        'relationship': 4852,
        'malware': 278,
        'attack-pattern': 244,
        'course-of-action': 241,
        'intrusion-set': 88,
        'tool': 56,
        'x-mitre-tactic': 12,
        'x-mitre-matrix': 1,
        'identity': 1,
        'marking-definition': 1
    })

In addition, you can access object properties for each object type and get more information about what is provided:

.. code-block:: python

    >>> object = enterprise_objects[0]
    >>> object.
    object.add_markings(          object.get_markings(          object.keys(                  object.properties_populated(  object.serialize(
    object.clear_markings(        object.is_marked(             object.new_version(           object.remove_markings(       object.set_markings(
    object.get(                   object.items(                 object.object_properties(     object.revoke(                object.values(

.. code-block:: python

    >>> object.object_properties()
    [
        'type',
        'id', 
        'created_by_ref',
        'created',
        'modified',
        'relationship_type',
        'description',
        'source_ref',
        'target_ref',
        'revoked',
        'labels',
        'external_references',
        'object_marking_refs',
        'granular_markings'
    ]

.. code-block:: python

    >>> object.properties_populated()
    [
        'object_marking_refs',
        'id',
        'external_references',
        'created',
        'modified',
        'type',
        'created_by_ref',
        'source_ref',
        'relationship_type',
        'target_ref',
        'revoked'
    ]

References
##########

* https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via
* https://oasis-open.github.io/cti-documentation/stix/intro
* https://docs.google.com/document/d/1IvkLxg_tCnICsatu2lyxKmWmh1gY2h8HUNssKIE-UIA/edit#heading=h.axjijf603msy
* https://github.com/mitre/cti/blob/master/USAGE.md#mapping-concepts
* https://stix2.readthedocs.io/en/latest/overview.html
* https://stix2.readthedocs.io/en/latest/api/datastore/stix2.datastore.filters.html