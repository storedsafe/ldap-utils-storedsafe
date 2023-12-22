# LDAP StoredSafe User Deactivation Script

The `ldap_deactivate.py` script scans an LDAP directory for users that match the search options in the provided config file.

See `ldap_deactivate.json` for an example configuration. Deactivated users can be found with the `userAccountControl:1.2.840.113556.1.4.803:=2` filter.

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
# Assuming your config file is called `config.json`
python3 ldap_deactivate.py -c config.json
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
- **match**: List of matching criteria.
  - **ldap**: Attribute name from LDAP user to match
  - **storedsafe**: Field name from StoredSafe user to match
