ATTACK CTI Overview
===================

The ATTACK-Python-Client project provides a python library named ``attackcti`` which wraps the functionality of `cti-python-stix2 <https://github.com/oasis-open/cti-python-stix2>`_ and `cti-taxii-client <https://github.com/oasis-open/cti-taxii-client>`_ libraries developed by MITRE.
This python wrapper allows ATT&CK users to query STIX content from the ATT&CK public TAXII server via pre-defined functions with a few lines of code.

Requirements
############

* Python3

Installation
############

The ``attackcti`` library can be installed via PIP:

.. code-block:: console

    $ pip install attackcti

Or you can install it from source:

.. code-block:: console

    $ git clone https://github.com/Cyb3rWard0g/ATTACK-Python-Client
    $ cd ATTACK-Python-Client
    $ pip install .

Quick Start
###########

You can simply import the ``attackcti`` library and start retrieving ATT&CK content in STIX from its public TAXII server::

    >>> from attackcti import attack_client
    >>>
    >>> lift = attack_client()
    >>> all_enterprise = lift.get_all_enterprise()
    >>>
    >>> len(all_enterprise)
    10
    >>>
    >>> all_enterprise.keys()
    dict_keys(['techniques', 'mitigations', 'groups', 'malware', 'tools', 'relationships', 'tactics', 'matrix', 'identity', 'marking-definition'])
    >>>
    >>> len(all_enterprise['techniques'])
    244
    >>>
    >>> all_enterprise["techniques"][0]
    AttackPattern(
        type='attack-pattern',
        id='attack-pattern--cf7b3a06-8b42-4c33-bbe9-012120027925',
        created_by_ref='identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5',
        created='2019-04-25T20:53:07.719Z',
        modified='2019-04-29T21:13:49.686Z',
        name='Compile After Delivery',
        description='Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Similar to [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027), text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution; typically via native utilities such as csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)\n\nSource code payloads may also be encrypted, encoded, and/or embedded within other files, such as those delivered as a [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193). Payloads may also be delivered in formats unrecognizable and inherently benign to the native OS (ex: EXEs on macOS/Linux) before later being (re)compiled into a proper executable binary with a bundled compiler and execution framework.(Citation: TrendMicro WindowsAppMac)\n',
        kill_chain_phases=[KillChainPhase
        (
            kill_chain_name='mitre-attack',
            phase_name='defense-evasion'
        )],
        external_references=[
            ExternalReference
            (
                source_name='mitre-attack',
                url='https://attack.mitre.org/techniques/T1500',
                external_id='T1500'
            ),
            ExternalReference
            (
                source_name='ClearSky MuddyWater Nov 2018',
                description='ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.',
                url='https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf'
            ),
            ExternalReference
            (
                source_name='TrendMicro WindowsAppMac',
                description='Trend Micro. (2019, February 11). Windows App Runs on Mac, Downloads Info Stealer and Adware. Retrieved April 25, 2019.',
                url='https://blog.trendmicro.com/trendlabs-security-intelligence/windows-app-runs-on-mac-downloads-info-stealer-and-adware/'
            )
        ],
        object_marking_refs=['marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'],
        x_mitre_contributors=['Ye Yint Min Thu Htut, Offensive Security Team, DBS Bank', 'Praetorian'],
        x_mitre_data_sources=['Process command-line parameters','Process monitoring', 'File monitoring'],
        x_mitre_defense_bypassed=['Static File Analysis', 'Binary Analysis', 'Anti-virus', 'Host intrusion prevention systems', 'Signature-based detection'],
        x_mitre_detection='Monitor the execution file paths and command-line arguments for common compilers, such as csc.exe and GCC/MinGW, and correlate with other suspicious behavior to reduce false positives from normal user and administrator behavior. The compilation of payloads may also generate file creation and/or file write events. Look for non-native binary formats and cross-platform compiler and execution frameworks like Mono and determine if they have a legitimate purpose on the system.(Citation: TrendMicro WindowsAppMac) Typically these should only be used in specific and limited cases, like for software development.',
        x_mitre_permissions_required=['User'],
        x_mitre_platforms=['Linux', 'macOS', 'Windows'],
        x_mitre_system_requirements=['Compiler software (either native to the system or delivered by the adversary)'],
        x_mitre_version='1.0'
    )

By default, the data returned by the available functions in the attackcti library is of type ``stix2``::

    >>> type(all_enterprise['techniques'][0])
    <class 'stix2.v20.sdo.AttackPattern'>

However, you can use the available ``stix_format`` parameter and set it to ``False``  to return a dictionary and with a more friendly field name schema as shown below::

    >>> all_enterprise_friendly = lift.get_all_enterprise(stix_format=False)
    >>>
    >>> type(all_enterprise_friendly['techniques'][0])
    <class 'dict'>
    >>>
    >>> len(all_enterprise_friendly['techniques'])
    244
    >>>
    >>> all_enterprise_friendly['techniques'][0]
    {
        'external_references': [
            {
                'external_id': 'T1500',
                'source_name': 'mitre-attack',
                'url': 'https://attack.mitre.org/techniques/T1500'
            }, 
            {
                'url': 'https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf',
                'source_name': 'ClearSky MuddyWater Nov 2018', 'description': 'ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.'
            }, 
            {
                'url': 'https://blog.trendmicro.com/trendlabs-security-intelligence/windows-app-runs-on-mac-downloads-info-stealer-and-adware/',
                'source_name': 'TrendMicro WindowsAppMac',
                'description': 'Trend Micro. (2019, February 11). Windows App Runs on Mac, Downloads Info Stealer and Adware. Retrieved April 25, 2019.'
            }
        ],
        'kill_chain_phases': [
            {
                'phase_name': 'defense-evasion',
                'kill_chain_name': 'mitre-attack'
            }
        ],
        'x_mitre_version': '1.0',
        'url': 'https://attack.mitre.org/techniques/T1500',
        'matrix': 'mitre-attack',
        'technique_id': 'T1500',
        'object_marking_refs': ['marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'],
        'type': 'attack-pattern', 
        'modified': '2019-04-29T21:13:49.686Z',
        'created_by_ref': 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5',
        'tactic': 'defense-evasion',
        'id': 'attack-pattern--cf7b3a06-8b42-4c33-bbe9-012120027925',
        'technique': 'Compile After Delivery',
        'created': '2019-04-25T20:53:07.719Z',
        'technique_description': 'Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Similar to [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027), text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution; typically via native utilities such as csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)\n\nSource code payloads may also be encrypted, encoded, and/or embedded within other files, such as those delivered as a [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193). Payloads may also be delivered in formats unrecognizable and inherently benign to the native OS (ex: EXEs on macOS/Linux) before later being (re)compiled into a proper executable binary with a bundled compiler and execution framework.(Citation: TrendMicro WindowsAppMac)\n',
        'contributors': ['Ye Yint Min Thu Htut, Offensive Security Team, DBS Bank', 'Praetorian'],
        'permissions_required': ['User'],
        'data_sources': ['Process command-line parameters', 'Process monitoring', 'File monitoring'],
        'technique_detection': 'Monitor the execution file paths and command-line arguments for common compilers, such as csc.exe and GCC/MinGW, and correlate with other suspicious behavior to reduce false positives from normal user and administrator behavior. The compilation of payloads may also generate file creation and/or file write events. Look for non-native binary formats and cross-platform compiler and execution frameworks like Mono and determine if they have a legitimate purpose on the system.(Citation: TrendMicro WindowsAppMac) Typically these should only be used in specific and limited cases, like for software development.',
        'platform': ['Linux', 'macOS', 'Windows'],
        'system_requirements': ['Compiler software (either native to the system or delivered by the adversary)'],
        'defense_bypassed': ['Static File Analysis', 'Binary Analysis', 'Anti-virus', 'Host intrusion prevention systems', 'Signature-based detection']
    }

Notebooks
#########

I put together a few Jupyte notebooks for you to learn a little bit more about a few of the functions available in the ``attackcti`` library:

* `Notebooks <https://github.com/Cyb3rWard0g/ATTACK-Python-Client/tree/master/notebooks>`_