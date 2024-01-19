# LDAP Utils StoredSafe

**This project is a WIP and is subject to change.**

This script collection provides a means to communicate between an LDAP server and StoredSafe.

The following scripts are currently available:

- deactivate
  - Deactivates StoredSafe users that match the LDAP users found based on your configuration file.
  - The filter `(userAccountControl:1.2.840.113556.1.4.803:=2)` can be used to detect deactivated users in LDAP.

## Requirements

- python3
- python3-venv
- git

## Setup

```bash
# Download dependencies
setup.sh
```

The `setup.sh` script will download all required python dependencies as well as the StoredSafe tokenhandler script.

To cleanup all downloaded dependencies, run `cleanup.sh`.

## Usage

```bash
# Deactivate users matching the criteria from config.json
python3 -m ldap_utils_storedsafe deactivate -c config.json
```

## Logging

Additional logging can be shown using the `LOG_LEVEL` environment variable with the following values:

- CRITICAL
- ERROR
- WARNING
- INFO
- DEBUG
- NOTSET

```bash
LOG_LEVEL=INFO python3 ldap_deactivate -c config.json
```

## Configuration

See `ldap_deactivate.json` for an example configuration file.

All available keys in the config files are described below:

- **ldap**: LDAP-related parameters.
  - **server_parameters**: Passed directly to the ldap3 Server object.
    (https://ldap3.readthedocs.io/en/latest/server.html)
  - **connection**: Passed directly to the ldap3 Connection object,
    along with the already defined server object.
    (https://ldap3.readthedocs.io/en/latest/connection.html)
  - **search**: List of search configurations.
    - **search_options**: List where each element is passed as parameters for individual calls to the
      ldap3 connection.extend.standard.paged_search() method.
      (https://ldap3.readthedocs.io/en/latest/standard.html)
    - **fields**: List of attributes to output
      - **attribute**: Name of attribute
      - (optional) **match**: Only use matched values, optionally capture first regex group
      - (optional) **replace**: List of search-replace values
- **convert**: List of criteria to convert LDAP fields to StoredSafe fields.
  - **ldap**: Attribute name from LDAP user to match
  - **storedsafe**: Field name from StoredSafe user to match
- **match**: List of StoredSafe field names that need to match with the values from the LDAP users.
