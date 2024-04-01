# Changelog

## [0.4.1](https://github.com/OTRF/ATTACK-Python-Client/tree/0.4.1) (2024-04-01)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.4.0...0.4.1)

**Implemented enhancements:**

- SSL certificate problem [\#56](https://github.com/OTRF/ATTACK-Python-Client/issues/56)
- Integrating examples from MITRE CTI - USAGE docs in GitHub [\#35](https://github.com/OTRF/ATTACK-Python-Client/issues/35)
- Create a function template for functions in attack\_client class  [\#34](https://github.com/OTRF/ATTACK-Python-Client/issues/34)
- Dynamic Interaction with stix2.v20.sdo object types [\#33](https://github.com/OTRF/ATTACK-Python-Client/issues/33)

**Fixed bugs:**

- AttributeError: 'function' object has no attribute 'query' when using get\_techniques\_used\_by\_group\_software [\#67](https://github.com/OTRF/ATTACK-Python-Client/issues/67)

**Closed issues:**

- 503 Error when client = attack\_client\(\) [\#72](https://github.com/OTRF/ATTACK-Python-Client/issues/72)
- Connection Timeout Issue When Using 'attackcti' Library [\#71](https://github.com/OTRF/ATTACK-Python-Client/issues/71)
- Expired certificate causes library crash [\#70](https://github.com/OTRF/ATTACK-Python-Client/issues/70)
- How to Access the Cloud ATT&CK Matrix [\#68](https://github.com/OTRF/ATTACK-Python-Client/issues/68)
- some external references are not available in technique data [\#32](https://github.com/OTRF/ATTACK-Python-Client/issues/32)
- \[TO-DO\] Add case insensitive features to some of the search functions  [\#25](https://github.com/OTRF/ATTACK-Python-Client/issues/25)

**Merged pull requests:**

- Updated Type Annotations and Docstrings [\#77](https://github.com/OTRF/ATTACK-Python-Client/pull/77) ([Cyb3rWard0g](https://github.com/Cyb3rWard0g))
- Removed double query method from COMPOSITE\_DS.query, fix \#67 [\#76](https://github.com/OTRF/ATTACK-Python-Client/pull/76) ([Cyb3rWard0g](https://github.com/Cyb3rWard0g))
- Improve STIX Object Handling and Documentation with Pydantic and Type Annotations [\#75](https://github.com/OTRF/ATTACK-Python-Client/pull/75) ([Cyb3rWard0g](https://github.com/Cyb3rWard0g))
- Adding `proxies` and `verify` parameters for TAXII Client [\#73](https://github.com/OTRF/ATTACK-Python-Client/pull/73) ([thelok](https://github.com/thelok))
- Update Dockerfile [\#69](https://github.com/OTRF/ATTACK-Python-Client/pull/69) ([halcyondream](https://github.com/halcyondream))
- use COMPOSITE\_DS instead of TC\_ENTERPRISE\_SOURCE in generic functions [\#66](https://github.com/OTRF/ATTACK-Python-Client/pull/66) ([rubinatorz](https://github.com/rubinatorz))

## [0.4.0](https://github.com/OTRF/ATTACK-Python-Client/tree/0.4.0) (2023-05-23)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.3.9...0.4.0)

**Merged pull requests:**

- Added support for Mobile data sources/components [\#65](https://github.com/OTRF/ATTACK-Python-Client/pull/65) ([rubinatorz](https://github.com/rubinatorz))

## [0.3.9](https://github.com/OTRF/ATTACK-Python-Client/tree/0.3.9) (2023-04-13)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.3.8...0.3.9)

**Merged pull requests:**

- Added ICS campaigns and some ICS fixes [\#64](https://github.com/OTRF/ATTACK-Python-Client/pull/64) ([rubinatorz](https://github.com/rubinatorz))

## [0.3.8](https://github.com/OTRF/ATTACK-Python-Client/tree/0.3.8) (2022-11-19)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.3.7...0.3.8)

**Implemented enhancements:**

- Should PRE-attack be removed? [\#59](https://github.com/OTRF/ATTACK-Python-Client/issues/59)

**Merged pull requests:**

- Add support for campaings entity added in MITRE v12 [\#62](https://github.com/OTRF/ATTACK-Python-Client/pull/62) ([dadokkio](https://github.com/dadokkio))
- added include\_pre\_attack parameter to attack\_client constructor [\#61](https://github.com/OTRF/ATTACK-Python-Client/pull/61) ([rubinatorz](https://github.com/rubinatorz))

## [0.3.7](https://github.com/OTRF/ATTACK-Python-Client/tree/0.3.7) (2022-07-05)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.3.6...0.3.7)

**Closed issues:**

- attack\_client not workning \(Err\_connection\) [\#58](https://github.com/OTRF/ATTACK-Python-Client/issues/58)
- Bug: enrich\_data\_sources is not working [\#57](https://github.com/OTRF/ATTACK-Python-Client/issues/57)

## [0.3.6](https://github.com/OTRF/ATTACK-Python-Client/tree/0.3.6) (2022-01-20)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.3.4.4...0.3.6)

**Implemented enhancements:**

- Removed Try Except features and set module to directly use CompositeDataSource queries [\#52](https://github.com/OTRF/ATTACK-Python-Client/issues/52)
- Updated SANS CTI Summit 2022 Notebook [\#51](https://github.com/OTRF/ATTACK-Python-Client/issues/51)
- Remove 'Pre' from get\_stix\_objects\(\) function [\#49](https://github.com/OTRF/ATTACK-Python-Client/issues/49)
- Update Navigator version in export\_groups\_navigator\_layers\(\) function to 4.5.5 [\#48](https://github.com/OTRF/ATTACK-Python-Client/issues/48)
- Update Jupyterbook config and toc file [\#47](https://github.com/OTRF/ATTACK-Python-Client/issues/47)
- Update Docs: Jupyter Notebooks explaining most of the functions available in the library [\#44](https://github.com/OTRF/ATTACK-Python-Client/issues/44)
- specify and update README.md file and requirements section [\#28](https://github.com/OTRF/ATTACK-Python-Client/issues/28)
- New parameters and Functions [\#41](https://github.com/OTRF/ATTACK-Python-Client/pull/41) ([Cyb3rPandaH](https://github.com/Cyb3rPandaH))

**Fixed bugs:**

- Remove function 'remove\_revoked\(\)' from available functions [\#46](https://github.com/OTRF/ATTACK-Python-Client/issues/46)
- Data sources enrichment function removes data sources metadata from techniques that do not have 'detects` relationships [\#45](https://github.com/OTRF/ATTACK-Python-Client/issues/45)
- Rename enrich\_data\_source function to enrich\_techniques\_data\_sources in get\_enterprise\_techniques [\#42](https://github.com/OTRF/ATTACK-Python-Client/issues/42)
- get\_software\_used\_by\_group returns all tools for groups with no actual tools/ software [\#27](https://github.com/OTRF/ATTACK-Python-Client/issues/27)

**Merged pull requests:**

- SANS CTI Summit 2022 Notebook \(Spanish\) [\#50](https://github.com/OTRF/ATTACK-Python-Client/pull/50) ([Cyb3rPandaH](https://github.com/Cyb3rPandaH))
- Update attack\_api.py [\#40](https://github.com/OTRF/ATTACK-Python-Client/pull/40) ([Cyb3rPandaH](https://github.com/Cyb3rPandaH))
- updated enterprise pre mobile and ics main functions and revoked and deprecated functions [\#39](https://github.com/OTRF/ATTACK-Python-Client/pull/39) ([Cyb3rWard0g](https://github.com/Cyb3rWard0g))
- added data sources function and field mappings [\#38](https://github.com/OTRF/ATTACK-Python-Client/pull/38) ([Cyb3rWard0g](https://github.com/Cyb3rWard0g))
- Add x-mitre-data-component [\#37](https://github.com/OTRF/ATTACK-Python-Client/pull/37) ([ZikyHD](https://github.com/ZikyHD))
- Update CONTRIBUTING.md [\#31](https://github.com/OTRF/ATTACK-Python-Client/pull/31) ([thegautamkumarjaiswal](https://github.com/thegautamkumarjaiswal))
- Feature Add and Update [\#26](https://github.com/OTRF/ATTACK-Python-Client/pull/26) ([thegautamkumarjaiswal](https://github.com/thegautamkumarjaiswal))
- Update for add proxy [\#10](https://github.com/OTRF/ATTACK-Python-Client/pull/10) ([charly837](https://github.com/charly837))

## [0.3.4.4](https://github.com/OTRF/ATTACK-Python-Client/tree/0.3.4.4) (2021-07-03)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.3.4.3...0.3.4.4)

**Closed issues:**

- Fail to convert "all\_techniques" to json file [\#23](https://github.com/OTRF/ATTACK-Python-Client/issues/23)
- Failed to pass a STIX object \(to another function\) that was retrieved by get\_object\_by\_attack\_id\(\) and get\_group\_by\_alias\(\) [\#20](https://github.com/OTRF/ATTACK-Python-Client/issues/20)
- group\_references missing [\#3](https://github.com/OTRF/ATTACK-Python-Client/issues/3)

**Merged pull requests:**

- added better support to handle stix filter results [\#30](https://github.com/OTRF/ATTACK-Python-Client/pull/30) ([Cyb3rWard0g](https://github.com/Cyb3rWard0g))

## [0.3.4.3](https://github.com/OTRF/ATTACK-Python-Client/tree/0.3.4.3) (2020-11-24)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.3.4...0.3.4.3)

**Closed issues:**

- Remove pre-ATT&CK or mark it as deprecated in the documentation [\#22](https://github.com/OTRF/ATTACK-Python-Client/issues/22)

## [0.3.4](https://github.com/OTRF/ATTACK-Python-Client/tree/0.3.4) (2020-11-24)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.3.3...0.3.4)

**Implemented enhancements:**

- Update SIX to six-1.15.0: No module named 'six.moves.collections\_abc' [\#19](https://github.com/OTRF/ATTACK-Python-Client/issues/19)
- Ability to retreive CAPEC IDs [\#1](https://github.com/OTRF/ATTACK-Python-Client/issues/1)

**Closed issues:**

- Add API for ICS domain [\#21](https://github.com/OTRF/ATTACK-Python-Client/issues/21)
- KeyError: 'v21' [\#18](https://github.com/OTRF/ATTACK-Python-Client/issues/18)

## [0.3.3](https://github.com/OTRF/ATTACK-Python-Client/tree/0.3.3) (2020-08-21)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.3.2...0.3.3)

**Fixed bugs:**

- get\_techniques\_used\_by\_all\_groups is broken by the new subtechniques change [\#14](https://github.com/OTRF/ATTACK-Python-Client/issues/14)

**Closed issues:**

- Tactic for T1506 is not present when calling `get_enterprise(stix_format=False)` [\#17](https://github.com/OTRF/ATTACK-Python-Client/issues/17)

**Merged pull requests:**

- Add requirements.txt [\#16](https://github.com/OTRF/ATTACK-Python-Client/pull/16) ([Neo23x0](https://github.com/Neo23x0))
- New function to remove deprecated STIX objects [\#15](https://github.com/OTRF/ATTACK-Python-Client/pull/15) ([marcusbakker](https://github.com/marcusbakker))

## [0.3.2](https://github.com/OTRF/ATTACK-Python-Client/tree/0.3.2) (2020-04-03)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.2.6...0.3.2)

**Closed issues:**

- MITRE TAXII server doesn't support 2.1, but 2.0. [\#12](https://github.com/OTRF/ATTACK-Python-Client/issues/12)
- The system cannot find the path specified: 'C:\\Program Files \(x86\)\\Microsoft Visual Studio 14.0\\VC\\PlatformSDK\\lib' [\#9](https://github.com/OTRF/ATTACK-Python-Client/issues/9)

**Merged pull requests:**

- Support for local STIX objects [\#11](https://github.com/OTRF/ATTACK-Python-Client/pull/11) ([rubinatorz](https://github.com/rubinatorz))

## [0.2.6](https://github.com/OTRF/ATTACK-Python-Client/tree/0.2.6) (2019-05-06)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.2.3...0.2.6)

## [0.2.3](https://github.com/OTRF/ATTACK-Python-Client/tree/0.2.3) (2019-05-02)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.2.1...0.2.3)

## [0.2.1](https://github.com/OTRF/ATTACK-Python-Client/tree/0.2.1) (2018-11-21)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/0.1.7...0.2.1)

**Closed issues:**

-  Jupyter notebooks Python 2 compatibility  [\#7](https://github.com/OTRF/ATTACK-Python-Client/issues/7)

**Merged pull requests:**

- Fix duplicate in requirements.txt [\#6](https://github.com/OTRF/ATTACK-Python-Client/pull/6) ([2xyo](https://github.com/2xyo))

## [0.1.7](https://github.com/OTRF/ATTACK-Python-Client/tree/0.1.7) (2018-11-06)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/1.3.6...0.1.7)

**Fixed bugs:**

- KeyError: 'created\_by\_ref' [\#4](https://github.com/OTRF/ATTACK-Python-Client/issues/4)

**Closed issues:**

- get\_all\_enterprise\(\) fails [\#5](https://github.com/OTRF/ATTACK-Python-Client/issues/5)

## [1.3.6](https://github.com/OTRF/ATTACK-Python-Client/tree/1.3.6) (2018-10-27)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/1.3.4...1.3.6)

## [1.3.4](https://github.com/OTRF/ATTACK-Python-Client/tree/1.3.4) (2018-06-15)

[Full Changelog](https://github.com/OTRF/ATTACK-Python-Client/compare/1479ef0fade015ad1ae522d4a1e91c5fe683a036...1.3.4)

**Fixed bugs:**

- using dict\(\) on a stix2 object will not correctly serialize datetime properties [\#2](https://github.com/OTRF/ATTACK-Python-Client/issues/2)



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
