# Azul Plugin Yara

Uses [yara-x](https://github.com/VirusTotal/yara-x) and a configurable ruleset to publish signature hits as AZUL features.

## Development Installation

To install azul-plugin-yara for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage

Usage on local files:

```bash
azul-plugin-yara -c yara_rules_path tests/rules -c security_override OFFICIAL -c name_suffix a -c version_suffix 2020.12.01 tests/data/test.txt
```

Example Output:

```
----- AzulPluginYara results -----
COMPLETED

events (1)

event for binary:b3c96d09b681a18b41b9eb99c8ccfc97acc432a2721f6dd9676183658a59f375:None
  {}
  output features:
                yararule: exploits.CVE313_unclass.Exploit_CVE_2015_0313
    yararule_description: exploits.CVE313_unclass.Exploit_CVE_2015_0313 - Looks for presence of code that could indicate ANGLER EK use of this flash vuln
        yararule_exploit: CVE-2015-0313
          yararule_match: exploits.CVE313_unclass.Exploit_CVE_2015_0313 - ZXhwbG9pdF9wcmltYXJvZGlhbF9maW5pc2go @ 0xc (offset)
  info:
    matches_key: ['rule', 'offset', 'var', 'value']
    matches: [['exploits.CVE313_unclass.Exploit_CVE_2015_0313', 12, '$', 'ZXhwbG9pdF9wcmltYXJvZGlhbF9maW5pc2go']]

Feature key:
  yararule:  Rule the string matched on from YARA
  yararule_description:  Description of the yara rule that hit
  yararule_exploit:  Yara rule metadata tagged exploits
  yararule_match:  Binary string signature match extracted by the labelling yara rule

```

Check `azul-plugin-yara --help` for advanced usage.

Automated usage in system:

```bash
azul-plugin-yara-scan --server http://dispatcher-dev.azul.local -c yara_rules_path tests/rules -c name_suffix a -c security_override OFFICIAL -c version_suffix 2020.12.01
```

### Plugin Config

| Config Name             | Default | Valid Values      | Description                                          |
| ----------------------- | ------- | ----------------- | ---------------------------------------------------- |
| filter_max_content_size | 200MiB  | pydantic.ByteSize | Maximum size of content to scan, otherwise skip.     |
| name_suffix             |         | \<str\>           | Ruleset name that will be used as suffix for plugin. |
| yara_rules_path \*      |         | \<filepath\>      | Filesystem path to directory with .yar rule files.   |
| version_suffix \*       |         | \<YYYY.MM.DD\>    | Version of rules as a date stamp.                    |
| security_override       | []      | \<str\>           | Security markings for the ruleset.                   |

\* = mandatory

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
