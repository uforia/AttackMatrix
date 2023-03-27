# MITRE ATT&CK API 2.0

## Introduction

AttackMatrix API is a Python module to interact with and explore MITRE's ATT&CK® matrices.

## Changelog

Version 2 improves on the original version:

- Initial cache generation time is now *seconds*(!) instead of minutes.
- Occasional 'overlap' bugs should be fixed.
- Code has been greatly simplified/improved to simplify MITRE ATT&CK parsing and lay some groundwork for upcoming features.
- All ATT&CK matrices are now merged into a single searchable tree, with presence in matrices noted in its `Matrices` property. Consequently, queries are now 'matrix-agnostic' and may yield more (interesting) results.
- Tree structure is now consistent:
  - `Metadata` list() field for names, descriptions, urls.
  - First level results are already sensible MITRE entities.
  - Subkey/-value pair levels are predictable: unfolded key/value pairs always reveal first-level relationships.

## Notes

- Webgrapher was not ported to the new version (2), as it was more of a Proof-of-Concept than a serious feature. I may return at some point the future. Currently, [MatterBot](https://github.com/uforia/MatterBot) may be able to provide you with the necessary graphs.
- Both **deprecated and 1.0 API** interfaces have been removed!
- You will need to update your code if you are using the old API endpoints.
- This is 'point-zero' release, so many bugs and edge-cases may pop up soon. Expect additional updates/patches!

## Licensing

- AttackMatrix: GPLv3

## Features

AttackMatrix can be:

- loaded as a module;
- run as a daemon, providing an HTTP JSON API endpoint for querying;
- run as a standalone script for generating a Python dict of a chosen matrix for use in other software.

The API offers an endpoint where loaded matrices can be queried through multiple functions. The API will return a Python dict or JSON object, depending your runtime invocation. Visit the API endpoint's root '/' for automatic OpenAPI documentation.

## Requirements

### For the API

1. `Python` 3.5+ (uses modern dictionary and `collections` features)
2. `Uvicorn`
3. `FastAPI`
4. At least one MITRE ATT&CK® matrix

## Installation

### For the API

1. `git clone` the repository
2. Install the dependencies: `pip3 install -r requirements.txt`
3. Edit the configuration in `config/settings.py.sample` and save it as `config/settings.py`
4. [Optional] Edit the configuration in `config/matrixtable.py` to your liking
5. Read the help: `./attackmatrix.py -h`
6. Download, transform and cache at least one matrix (default: `Enterprise`) using `./attackmatrix.py -t ...`

## Comments and Suggestions

If you have ideas for improvements or general feedback, please reach out to the [author](mailto:uforia@dhcp.net).

## Known issues

- Nothing currently!

## Thanks

- MITRE, obviously, for their outstanding work on and sharing of ATT&CK - [MITRE® ATT&CK](https://attack.mitre.org)
