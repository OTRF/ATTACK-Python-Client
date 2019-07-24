Library Functions
=================

get_enterprise
##############

get_enterprise(self, stix_format=True)
**************************************

Extracts all the available STIX objects in the Enterprise ATT&CK matrix categorized in the following way:

+--------------------+---------------------+
| ATT&CK Format      | STIX Format         |
+====================+=====================+
| technique          | attack-pattern      |
+--------------------+---------------------+
| mitigation         | course-of-action    |
+--------------------+---------------------+
| group              | intrusion-set       |
+--------------------+---------------------+
| malware            | malware             |
+--------------------+---------------------+
| tool               | tool                |
+--------------------+---------------------+
| relationship       | relationship        |
+--------------------+---------------------+
| tactic             | x-mitre-tactic      |
+--------------------+---------------------+
| matrix             | x-mitre-tactic      |
+--------------------+---------------------+
| identity           | identity            |
+--------------------+---------------------+
| marking-definition | markinng-definition |
+--------------------+---------------------+

Parameters:

    * ``stix_format``: returns results in original STIX format or friendly syntax ('attack-pattern' or 'technique')

Returns: Dictionary

Examples
********

>>> from attackcti import attack_client
>>> lift = attack_client()
>>>
>>> enterprise = lift.get_enterprise()
>>> type(enterprise)
<class 'dict'>
>>>
>>> enterprise.keys()
dict_keys(['techniques', 'mitigations', 'groups', 'malware', 'tools', 'relationships', 'tactics', 'matrix', 'identity', 'marking-definition'])
>>>
>>> type(enterprise['techniques'])
<class 'list'>
>>> type(enterprise['techniques'][0])
<class 'stix2.v20.sdo.AttackPattern'>
>>>
>>> print(enterprise['techniques'][0])
{
    "type": "attack-pattern",
    "id": "attack-pattern--cf7b3a06-8b42-4c33-bbe9-012120027925",
    "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    "created": "2019-04-25T20:53:07.719Z",
    "modified": "2019-04-29T21:13:49.686Z",
    "name": "Compile After Delivery",
    "description": "Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Similar to [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027), text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution; typically via native utilities such as csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)\n\nSource code payloads may also be encrypted, encoded, and/or embedded within other files, such as those delivered as a [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193). Payloads may also be delivered in formats unrecognizable and inherently benign to the native OS (ex: EXEs on macOS/Linux) before later being (re)compiled into a proper executable binary with a bundled compiler and execution framework.(Citation: TrendMicro WindowsAppMac)\n",
    "kill_chain_phases": [
        {
            "kill_chain_name": "mitre-attack",
            "phase_name": "defense-evasion"
        }
    ],
    "external_references": [
        {
            "source_name": "mitre-attack",
            "url": "https://attack.mitre.org/techniques/T1500",
            "external_id": "T1500"
        },
        {
            "source_name": "ClearSky MuddyWater Nov 2018",
            "description": "ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.",
            "url": "https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf"
        },
        {
            "source_name": "TrendMicro WindowsAppMac",
            "description": "Trend Micro. (2019, February 11). Windows App Runs on Mac, Downloads Info Stealer and Adware. Retrieved April 25, 2019.",
            "url": "https://blog.trendmicro.com/trendlabs-security-intelligence/windows-app-runs-on-mac-downloads-info-stealer-and-adware/"
        }
    ],
    "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
    ],
    "x_mitre_contributors": [
        "Ye Yint Min Thu Htut, Offensive Security Team, DBS Bank",
        "Praetorian"
    ],
    "x_mitre_data_sources": [
        "Process command-line parameters",
        "Process monitoring",
        "File monitoring"
    ],
    "x_mitre_defense_bypassed": [
        "Static File Analysis",
        "Binary Analysis",
        "Anti-virus",
        "Host intrusion prevention systems",
        "Signature-based detection"
    ],
    "x_mitre_detection": "Monitor the execution file paths and command-line arguments for common compilers, such as csc.exe and GCC/MinGW, and correlate with other suspicious behavior to reduce false positives from normal user and administrator behavior. The compilation of payloads may also generate file creation and/or file write events. Look for non-native binary formats and cross-platform compiler and execution frameworks like Mono and determine if they have a legitimate purpose on the system.(Citation: TrendMicro WindowsAppMac) Typically these should only be used in specific and limited cases, like for software development.",
    "x_mitre_permissions_required": [
        "User"
    ],
    "x_mitre_platforms": [
        "Linux",
        "macOS",
        "Windows"
    ],
    "x_mitre_system_requirements": [
        "Compiler software (either native to the system or delivered by the adversary)"
    ],
    "x_mitre_version": "1.0"
}

get_enterprise_techniques
#########################

get_enterprise_techniques(self, stix_format=True)
*************************************************

Extracts all the available techniques STIX objects in the Enterprise ATT&CK matrix

Parameters:

    * ``stix_format``: returns results in original STIX format or friendly syntax ('attack-pattern' or 'technique')

Returns: List of stix2 objects

Examples
********

>>> from attackcti import attack_client
>>> lift = attack_client()
>>>
>>> enterprise_techniques = lift.get_enterprise_techniques()
>>> type(enterprise_techniques)
<class 'list'>
>>>
>>> type(enterprise_techniques[0])
<class 'stix2.v20.sdo.AttackPattern'>
>>>
>>> print(enterprise_techniques[0])
{
    "type": "attack-pattern",
    "id": "attack-pattern--cf7b3a06-8b42-4c33-bbe9-012120027925",
    "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    "created": "2019-04-25T20:53:07.719Z",
    "modified": "2019-04-29T21:13:49.686Z",
    "name": "Compile After Delivery",
    "description": "Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Similar to [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027), text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution; typically via native utilities such as csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)\n\nSource code payloads may also be encrypted, encoded, and/or embedded within other files, such as those delivered as a [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193). Payloads may also be delivered in formats unrecognizable and inherently benign to the native OS (ex: EXEs on macOS/Linux) before later being (re)compiled into a proper executable binary with a bundled compiler and execution framework.(Citation: TrendMicro WindowsAppMac)\n",
    "kill_chain_phases": [
        {
            "kill_chain_name": "mitre-attack",
            "phase_name": "defense-evasion"
        }
    ],
    "external_references": [
        {
            "source_name": "mitre-attack",
            "url": "https://attack.mitre.org/techniques/T1500",
            "external_id": "T1500"
        },
        {
            "source_name": "ClearSky MuddyWater Nov 2018",
            "description": "ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.",
            "url": "https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf"
        },
        {
            "source_name": "TrendMicro WindowsAppMac",
            "description": "Trend Micro. (2019, February 11). Windows App Runs on Mac, Downloads Info Stealer and Adware. Retrieved April 25, 2019.",
            "url": "https://blog.trendmicro.com/trendlabs-security-intelligence/windows-app-runs-on-mac-downloads-info-stealer-and-adware/"
        }
    ],
    "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
    ],
    "x_mitre_contributors": [
        "Ye Yint Min Thu Htut, Offensive Security Team, DBS Bank",
        "Praetorian"
    ],
    "x_mitre_data_sources": [
        "Process command-line parameters",
        "Process monitoring",
        "File monitoring"
    ],
    "x_mitre_defense_bypassed": [
        "Static File Analysis",
        "Binary Analysis",
        "Anti-virus",
        "Host intrusion prevention systems",
        "Signature-based detection"
    ],
    "x_mitre_detection": "Monitor the execution file paths and command-line arguments for common compilers, such as csc.exe and GCC/MinGW, and correlate with other suspicious behavior to reduce false positives from normal user and administrator behavior. The compilation of payloads may also generate file creation and/or file write events. Look for non-native binary formats and cross-platform compiler and execution frameworks like Mono and determine if they have a legitimate purpose on the system.(Citation: TrendMicro WindowsAppMac) Typically these should only be used in specific and limited cases, like for software development.",
    "x_mitre_permissions_required": [
        "User"
    ],
    "x_mitre_platforms": [
        "Linux",
        "macOS",
        "Windows"
    ],
    "x_mitre_system_requirements": [
        "Compiler software (either native to the system or delivered by the adversary)"
    ],
    "x_mitre_version": "1.0"
}

get_enterprise_mitigations
##########################

get_enterprise_mitigations(self, stix_format=True)
**************************************************

Extracts all the available mitigations STIX objects in the Enterprise ATT&CK matrix

Parameters:

    * ``stix_format``: returns results in original STIX format or friendly syntax ('attack-pattern' or 'technique')

Returns: List of stix2 objects

Examples
********

>>> from attackcti import attack_client
>>> lift = attack_client()
>>>
>>> enterprise_mitigations = lift.get_enterprise_mitigations()
>>> type(enterprise_mitigations)
<class 'list'>
>>> 
>>> type(enterprise_mitigations[0])
<class 'stix2.v20.sdo.CourseOfAction'>
>>> 
>>> print(enterprise_mitigations[0])
{
    "type": "course-of-action",
    "id": "course-of-action--70886857-0f19-4caa-b081-548354a8a994",
    "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    "created": "2019-04-26T19:30:33.607Z",
    "modified": "2019-04-26T19:41:45.126Z",
    "name": "Firmware Corruption Mitigation",
    "description": "Prevent adversary access to privileged accounts or access necessary to perform this technique. Check the integrity of the existing BIOS and device firmware to determine if it is vulnerable to modification. Patch the BIOS and other firmware as necessary to prevent successful use of known vulnerabilities. ",
    "external_references": [
        {
            "source_name": "mitre-attack",
            "url": "https://attack.mitre.org/techniques/T1495",
            "external_id": "T1495"
        }
    ],
    "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
    ],
    "x_mitre_version": "1.0"
}

get_enterprise_groups
#####################

get_enterprise_groups(self, stix_format=True)
*********************************************

Extracts all the available groups STIX objects in the Enterprise ATT&CK matrix

Parameters:

    * ``stix_format``: returns results in original STIX format or friendly syntax ('attack-pattern' or 'technique')

Returns: List of stix2 objects

Examples
********

>>> from attackcti import attack_client
>>> lift = attack_client()
>>>
>>> enterprise_groups = lift.get_enterprise_groups()
>>> type(enterprise_groups)
<class 'list'>
>>> 
>>> type(enterprise_groups[0])
<class 'stix2.v20.sdo.IntrusionSet'>
>>> 
>>> print(enterprise_groups[0])
{
    "type": "intrusion-set",
    "id": "intrusion-set--9538b1a4-4120-4e2d-bf59-3b11fcab05a4",
    "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    "created": "2019-04-16T15:14:38.533Z",
    "modified": "2019-04-29T18:59:16.079Z",
    "name": "TEMP.Veles",
    "description": "[TEMP.Veles](https://attack.mitre.org/groups/G0088) is a Russia-based threat group that has targeted critical infrastructure. The group has been observed utilizing TRITON, a malware framework designed to manipulate industrial safety systems.(Citation: FireEye TRITON 2019)(Citation: FireEye TEMP.Veles 2018)(Citation: FireEye TEMP.Veles JSON April 2019)",
    "aliases": [
        "TEMP.Veles",
        "XENOTIME"
    ],
    "external_references": [
        {
            "source_name": "mitre-attack",
            "url": "https://attack.mitre.org/groups/G0088",
            "external_id": "G0088"
        },
        {
            "source_name": "TEMP.Veles",
            "description": "(Citation: FireEye TRITON 2019)"
        },
        {
            "source_name": "XENOTIME",
            "description": "The activity group XENOTIME, as defined by Dragos, has overlaps with activity reported upon by FireEye about TEMP.Veles as well as the actors behind TRITON.(Citation: Dragos Xenotime 2018)(Citation: Pylos Xenotime 2019)(Citation: FireEye TRITON 2019)(Citation: FireEye TEMP.Veles 2018 )"
        },
        {
            "source_name": "FireEye TRITON 2019",
            "description": "Miller, S, et al. (2019, April 10). TRITON Actor TTP Profile, Custom Attack Tools, Detections, and ATT&CK Mapping. Retrieved April 16, 2019.",
            "url": "https://www.fireeye.com/blog/threat-research/2019/04/triton-actor-ttp-profile-custom-attack-tools-detections.html"
        },
        {
            "source_name": "FireEye TEMP.Veles 2018",
            "description": "FireEye Intelligence . (2018, October 23). TRITON Attribution: Russian Government-Owned Lab Most Likely Built Custom Intrusion Tools for TRITON Attackers. Retrieved April 16, 2019.",
            "url": "https://www.fireeye.com/blog/threat-research/2018/10/triton-attribution-russian-government-owned-lab-most-likely-built-tools.html "
        },
        {
            "source_name": "FireEye TEMP.Veles JSON April 2019",
            "description": "Miller, S., et al. (2019, April 10). TRITON Appendix C. Retrieved April 29, 2019.",
            "url": "https://www.fireeye.com/content/dam/fireeye-www/blog/files/TRITON_Appendix_C.html"
        },
        {
            "source_name": "Dragos Xenotime 2018",
            "description": "Dragos, Inc.. (n.d.). Xenotime. Retrieved April 16, 2019.",
            "url": "https://dragos.com/resource/xenotime/"
        },
        {
            "source_name": "Pylos Xenotime 2019",
            "description": "Slowik, J.. (2019, April 12). A XENOTIME to Remember: Veles in the Wild. Retrieved April 16, 2019.",
            "url": "https://pylos.co/2019/04/12/a-xenotime-to-remember-veles-in-the-wild/"
        },
        {
            "source_name": "FireEye TEMP.Veles 2018 ",
            "description": "FireEye Intelligence . (2018, October 23). TRITON Attribution: Russian Government-Owned Lab Most Likely Built Custom Intrusion Tools for TRITON Attackers. Retrieved April 16, 2019.",
            "url": "https://www.fireeye.com/blog/threat-research/2018/10/triton-attribution-russian-government-owned-lab-most-likely-built-tools.html "
        }
    ],
    "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
    ],
    "x_mitre_version": "1.0"
}

get_all_enterprise_malware
##########################

get_all_enterprise_malware(self, stix_format=True)
**************************************************

Extracts all the available malware STIX objects in the Enterprise ATT&CK matrix

Parameters:

    * ``stix_format``: returns results in original STIX format or friendly syntax ('attack-pattern' or 'technique')

Returns: List of stix2 objects

Examples
********

>>> from attackcti import attack_client
>>> lift = attack_client()
>>>
>>> enterprise_malware = lift.get_all_enterprise_malware()         
>>> type(enterprise_malware)
<class 'list'>
>>> 
>>> type(enterprise_malware[0])
<class 'stix2.v20.sdo.Malware'>
>>> 
>>> print(enterprise_malware[0])
{
    "type": "malware",
    "id": "malware--d1531eaa-9e17-473e-a680-3298469662c3",
    "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    "created": "2019-04-23T18:41:36.914Z",
    "modified": "2019-04-29T21:19:34.739Z",
    "name": "CoinTicker",
    "description": "[CoinTicker](https://attack.mitre.org/software/S0369) is a malicious application that poses as a cryptocurrency price ticker and installs components of the open source backdoors EvilOSX and EggShell.(Citation: CoinTicker 2019)",
    "labels": [
        "malware"
    ],
    "external_references": [
        {
            "source_name": "mitre-attack",
            "url": "https://attack.mitre.org/software/S0369",
            "external_id": "S0369"
        },
        {
            "source_name": "CoinTicker 2019",
            "description": "Thomas Reed. (2018, October 29). Mac cryptocurrency ticker app installs backdoors. Retrieved April 23, 2019.",
            "url": "https://blog.malwarebytes.com/threat-analysis/2018/10/mac-cryptocurrency-ticker-app-installs-backdoors/"
        }
    ],
    "object_marking_refs": [
        "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
    ],
    "x_mitre_aliases": [
        "CoinTicker"
    ],
    "x_mitre_contributors": [
        "Richie Cyrus, SpecterOps"
    ],
    "x_mitre_platforms": [
        "macOS"
    ],
    "x_mitre_version": "1.0"
}

get_data_sources
################

get_data_sources(self)
**********************

Extracts all data sources mapped to techniques across all matrices.

Returns: List

Examples
********

>>> from attackcti import attack_client
>>> lift = attack_client()
>>>
>>> lift.get_data_sources()
['Process command-line parameters', 'Process monitoring', 'File monitoring', 'SSL/TLS inspection', 
'Web logs', 'Web application firewall logs', 'Network intrusion detection system', 'Network protocol analysis', 
'Network device logs', 'Netflow/Enclave netflow', 'Sensor health and status', 'Process use of network', 
'BIOS', 'Component firmware', 'Packet capture', 'Application logs', 'Windows Registry', 'Services', 
'Windows event logs', 'API monitoring', 'Kernel drivers', 'MBR', 'DNS records', 'PowerShell logs', 
'Anti-virus', 'Email gateway', 'DLL monitoring', 'Authentication logs', 'Web proxy', 'Windows Error Reporting', 
'System calls', 'Data loss prevention', 'Third-party application logs', 'Binary file metadata', 
'Asset management', 'Detonation chamber', 'Mail server', 'Loaded DLLs', 'Browser extensions', 
'Access tokens', 'Environment variable', 'User interface', 'Malware reverse engineering',
'Digital certificate logs', 'Disk forensics', 'Host network interface', 'WMI Objects', 'VBR', 'Named Pipes', 'EFI']

get_techniques_by_datasources
#############################

get_techniques_by_datasources(self, *args, stix_format=True)
************************************************************

Extracts all techniques mapped to one or multiple data sources.

Parameters:

    * ``*args``: one or more data sources ("datasource1", "datsasource2")
    * ``stix_format``: returns results in original STIX format or friendly syntax ('attack-pattern' or 'technique')

Returns: List

Examples
********

>>> from attackcti import attack_client
>>> lift = attack_client()

>>> techniques = lift.get_techniques_by_datasources("windows event logs")
>>> len(techniques)
22
>>> for t in techniques:
...     print(t['name'],t['x_mitre_data_sources'])
... 
Inhibit System Recovery ['Windows Registry', 'Services', 'Windows event logs', 'Process command-line parameters', 'Process monitoring']
Group Policy Modification ['Windows event logs']
File Permissions Modification ['File monitoring', 'Process monitoring', 'Process command-line parameters', 'Windows event logs']
BITS Jobs ['API monitoring', 'Packet capture', 'Windows event logs']
CMSTP ['Process monitoring', 'Process command-line parameters', 'Process use of network', 'Windows event logs']
Control Panel Items ['API monitoring', 'Binary file metadata', 'DLL monitoring', 'Windows Registry', 'Windows event logs', 'Process command-line parameters', 'Process monitoring']
Indirect Command Execution ['File monitoring', 'Process monitoring', 'Process command-line parameters', 'Windows event logs']
Kerberoasting ['Windows event logs']
SIP and Trust Provider Hijacking ['API monitoring', 'Application logs', 'DLL monitoring', 'Loaded DLLs', 'Process monitoring', 'Windows Registry', 'Windows event logs']
Distributed Component Object Model ['API monitoring', 'Authentication logs', 'DLL monitoring', 'Packet capture', 'Process monitoring', 'Windows Registry', 'Windows event logs']
Dynamic Data Exchange ['API monitoring', 'DLL monitoring', 'Process monitoring', 'Windows Registry', 'Windows event logs']
Hooking ['API monitoring', 'Binary file metadata', 'DLL monitoring', 'Loaded DLLs', 'Process monitoring', 'Windows event logs']
Image File Execution Options Injection ['Process monitoring', 'Windows Registry', 'Windows event logs']
LLMNR/NBT-NS Poisoning and Relay ['Windows event logs', 'Windows Registry', 'Packet capture', 'Netflow/Enclave netflow']
SID-History Injection ['API monitoring', 'Authentication logs', 'Windows event logs']
Create Account ['Process monitoring', 'Process command-line parameters', 'Authentication logs', 'Windows event logs']
Modify Registry ['Windows Registry', 'File monitoring', 'Process monitoring', 'Process command-line parameters', 'Windows event logs']
Account Manipulation ['Authentication logs', 'API monitoring', 'Windows event logs', 'Packet capture']
Indicator Removal on Host ['File monitoring', 'Process monitoring', 'Process command-line parameters', 'API monitoring', 'Windows event logs']
Scheduled Task ['File monitoring', 'Process monitoring', 'Process command-line parameters', 'Windows event logs']
New Service ['Windows Registry', 'Process monitoring', 'Process command-line parameters', 'Windows event logs']
Obfuscated Files or Information ['Network protocol analysis', 'Process use of network', 'File monitoring', 
'Malware reverse engineering', 'Binary file metadata', 'Process command-line parameters', 'Environment variable', 
'Process monitoring', 'Windows event logs', 'Network intrusion detection system', 'Email gateway', 'SSL/TLS inspection']