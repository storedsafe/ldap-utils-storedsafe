"""
Searches for LDAP users and StoredSafe users based on the provided config.
Outputs and queries are specified in a json file with the following keys:
    - ldap: LDAP-related parameters.
        - server_parameters: Passed directly to the ldap3 Server object.
            (https://ldap3.readthedocs.io/en/latest/server.html)
        - connection: Passed directly to the ldap3 Connection object,
            along with the already defined server object.
            (https://ldap3.readthedocs.io/en/latest/connection.html)
        - search: List of search configurations.
            - search_options: List where each element is passed as parameters for individual calls to the
                ldap3 connection.extend.standard.paged_search() method.
                (https://ldap3.readthedocs.io/en/latest/standard.html)
            - fields: List of attributes to output
                - attribute: Name of attribute
                - (optional) match: Only use matched values, optionally capture first regex group
                - (optional) replace: List of search-replace values
    - match: List of matching criteria.
        - ldap: Attribute name from LDAP user to match
        - storedsafe: Field name from StoredSafe user to match
    - convert: List of fields that should be converted from LDAP terms to StoredSafe terms.
        - ldap: Attribute name from LDAP user to match
        - storedsafe: Field name from StoredSafe user to match
    - match: List of fields that should match in StoredSafe-terms. See `convert`.

Logging levels can be adjusted using the `LOG_LEVEL` environment variable with the following options:
    - CRITICAL
    - ERROR
    - WARNING
    - INFO
    - DEBUG
    - NOTSET
"""

from typing import List
from pathlib import Path
from argparse import ArgumentParser
from ldap3 import Server, Connection
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError
from storedsafe import StoredSafe, TokenUndefinedException
from . import tokenhandler
import os
import sys
import logging
import json
import re

### Helper Functions ###


def get_logger(name):
    """
    Returns a logging object with the given name.
    """
    logger = logging.getLogger(name)
    logger.setLevel(os.getenv('LOG_LEVEL') or logging.INFO)
    return logger


def fatal_error(code, msg):
    """
    Logs a message with log level ERROR and exits the application with
    the provided exit code.
    """
    LOGGER.error(f"{code} {msg}")
    sys.exit(code)


### Setup Logging ###


logging.basicConfig()
LOGGER = get_logger('utils')


### Error codes ###

ERROR_OUTPUT_UNEXPECTED = 1
ERROR_OUTPUT_PATH = 2
ERROR_OUTPUT_ATTRIBUTE = 3

ERROR_CONNECT_UNEXPECTED = 11
ERROR_CONNECT_BIND = 12
ERROR_CONNECT_TIMEOUT = 13

ERROR_CONFIG_UNEXPECTED = 21
ERROR_CONFIG_PATH = 22
ERROR_CONFIG_JSON = 23


### Constants ###

RC_PATH = Path.home() / '.storedsafe-client.rc'
BIT_ACTIVE = 1 << 7


### Application ###

def filter_values(values, match, replace):
    """
    Filters and modifies provided values based on the provided regex for matching
    and replace filters. If filters are not provided, that filter step will be skipped.
    """
    matched_values = []
    if match:
        pattern = re.compile(match)
        for value in values:
            matched_value = re.match(pattern, value)
            if matched_value:
                if len(matched_value.groups()) == 0:
                    matched_values.append(matched_value.group(0))
                else:
                    matched_values.append(matched_value.group(1))
    else:
        matched_values = values

    if replace:
        for search, repl in replace:
            pattern = re.compile(search)
            for i, value in enumerate(matched_values):
                matched_values[i] = re.sub(pattern, repl, value)

    return matched_values


def get_ldap_users(conn, fields, search_options):
    """
    Queries the LDAP server for the users with the given parameters and attributes.
    """
    ldap_users = []
    attributes = [field['attribute'] for field in fields]
    try:
        for options in search_options:
            for entry in conn.extend.standard.paged_search(**options, attributes=attributes):
                user = {}
                for field in fields:
                    values = entry['attributes'][field['attribute']]
                    rows = set(filter_values(values, field.get(
                        'match'), field.get('replace')))
                    user[field['attribute']] = list(rows)
                ldap_users.append(user)

    except IndexError as e:
        LOGGER.debug(entry['attributes'])
        fatal_error(ERROR_OUTPUT_ATTRIBUTE,
                    f"Invalid attribute ({e})")
    except Exception as e:
        fatal_error(ERROR_OUTPUT_UNEXPECTED,
                    f"Unexpected error while searching for users ({e})")
    else:
        LOGGER.info(f"Successfully fetched {len(ldap_users)} LDAP users.")
    return ldap_users


def get_storedsafe_users(api: StoredSafe):
    """
    Get all StoredSafe users with the active flag set.
    """
    res = api.list_users()
    data = res.json()
    users = [
        user for user in data['CALLINFO']['users']
        if int(user['status']) & BIT_ACTIVE > 0
    ]
    LOGGER.info(f"Successfully fetched {len(users)} StoredSafe users.")
    return users


def ldap_to_storedsafe(ldap_users, convert_criteria: List[dict]):
    """
    Converts LDAP fields to StoredSafe fields based on the provided criteria.
    """
    converted_users = []
    for ldap_user in ldap_users:
        converted_users.append({
            field['storedsafe']: ldap_user[field['ldap']][0]
            for field in convert_criteria
            if field['ldap'] in ldap_user
        })
    return converted_users


def get_matched_users(converted_users, storedsafe_users, match_criteria):
    """
    Gets users matched from LDAP to StoredSafe based on the provided criteria.
    All criteria must match for the user to be considered a match.
    """
    matched_users = []
    for ldap_user in converted_users:
        for storedsafe_user in storedsafe_users:
            is_match = True
            # Match user only if all criteria match
            for key in match_criteria:
                if ldap_user[key] != storedsafe_user[key]:
                    is_match = False
            if is_match:
                matched_users.append(storedsafe_user)
    return matched_users


def ldap_connect(server_params, connection_params):
    """
    Sets and binds the connection to the LDAP server with the given parameters.
    """
    server = Server(**server_params)
    try:
        return Connection(server, **connection_params, auto_bind=True)
    except LDAPBindError as e:
        fatal_error(ERROR_CONNECT_BIND, f"Unable to authenticate ({e})")
    except LDAPSocketOpenError as e:
        fatal_error(ERROR_CONNECT_TIMEOUT,
                    f"Unable to reach host `{server.host}` ({e})")
    except Exception as e:
        fatal_error(ERROR_CONNECT_UNEXPECTED,
                    f"Unexpected error while connecting to host ({e})")


def storedsafe_login() -> StoredSafe:
    if RC_PATH.is_file():
        api = StoredSafe.from_rc(RC_PATH)
        try:
            res = api.check()
            data = res.json()
            if data['CALLINFO']['status'] == 'SUCCESS':
                return api
        except TokenUndefinedException:
            LOGGER.info("No valid token found, logging in...")
        else:
            LOGGER.info("No token found, logging in...")
    else:
        LOGGER.info("No RC file found, logging in for the first time...")
    _argv = sys.argv
    sys.argv = ['tokenhandler', 'login']
    _stdout = sys.stdout
    sys.stdout = sys.stderr
    tokenhandler.main()
    sys.argv = _argv
    sys.stdout = _stdout
    return StoredSafe.from_rc(RC_PATH)


def get_config(path):
    """
    Reads the JSON config file from the specified path. See the docstring at the
    top of this document for a specification for the config file.
    """
    try:
        with Path(path).open('r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        fatal_error(ERROR_CONFIG_PATH, f"Invalid path `{path}`")
    except json.decoder.JSONDecodeError as e:
        fatal_error(ERROR_CONFIG_JSON,
                    f"Failed to parse JSON in config ({e})")
    except Exception as e:
        fatal_error(ERROR_CONFIG_UNEXPECTED,
                    f"Unexpected error while reading config ({e})")


def run_search(config_path: str | Path) -> ((Connection, list), (StoredSafe, list), (list, list)):
    config = get_config(config_path)
    ldap = ldap_connect(
        config['ldap']['server_parameters'],
        config['ldap']['connection_parameters']
    )
    storedsafe = storedsafe_login()

    ldap_users = []
    for search_options in config['ldap']['search']:
        ldap_users.extend(get_ldap_users(ldap, **search_options))
    storedsafe_users = get_storedsafe_users(storedsafe)
    converted_users = ldap_to_storedsafe(ldap_users, config['convert'])
    matched_users = get_matched_users(
        converted_users, storedsafe_users, config['match'])

    return (
        (ldap, ldap_users),
        (storedsafe, storedsafe_users),
        (converted_users, matched_users),
    )
