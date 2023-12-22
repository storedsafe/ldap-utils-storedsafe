#!/usr/bin/python3
"""
Performs one or more LDAP searches and puts the returned mail attributes
in the designated files along with a message for each row.

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
"""

__author__ = "Oscar Mattsson <oscar@storedsafe.com>"
__version__ = "0.0.1"
__date__ = "2023-12-13"
__change__ = "2023-12-13"
__license__ = "MIT"

from pathlib import Path
from argparse import ArgumentParser
from ldap3 import Server, Connection
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError
from storedsafe import StoredSafe, TokenUndefinedException
import tokenhandler
import os
import sys
import logging
import json
import re

### Setup Logging ###


logging.basicConfig()
LOGGER = logging.getLogger('mail-list')
LOGGER.setLevel(os.getenv('LOG_LEVEL') or logging.ERROR)


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


### Helper Functions ###

def _fatal_error(code, msg):
    """
    Logs a message with log level ERROR and exits the application with
    the provided exit code.
    """
    LOGGER.error(f"{code} {msg}")
    sys.exit(code)


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
        _fatal_error(ERROR_OUTPUT_ATTRIBUTE,
                     f"Invalid attribute ({e})")
    except Exception as e:
        _fatal_error(ERROR_OUTPUT_UNEXPECTED,
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


def get_matched_users(ldap_users, storedsafe_users, match_criteria):
    """
    Gets users matched from LDAP to StoredSafe based on the provided criteria.
    All criteria must match for the user to be considered a match.
    """
    matched_users = []
    for deactivated_user in ldap_users:
        for storedsafe_user in storedsafe_users:
            is_match = True
            # Match user only if all criteria match
            for match_criterion in match_criteria:
                d_values = deactivated_user[match_criterion['ldap']]
                s_value = storedsafe_user[match_criterion['storedsafe']]
                has_match = False
                for value in d_values:
                    if s_value == value:
                        has_match = True
                        break
                if not has_match:
                    is_match = False
                    break
            if is_match:
                matched_users.append(storedsafe_user)
    LOGGER.info(f"Matched {len(matched_users)} to be deactivated.")
    return matched_users


def deactivate_storedsafe_users(api: StoredSafe, users):
    """
    Unset the active flag on the provided StoredSafe user accounts.
    """
    for user in users:
        status = int(user['status']) ^ BIT_ACTIVE
        LOGGER.info(f"Deactivating {user['username']} ({user['id']})")
        LOGGER.debug(
            f"User: {user['id']}, Status: {int(user['status'])} -> {status}")
        api.edit_user(user['id'], status=status)


def ldap_connect(server_params, connection_params):
    """
    Sets and binds the connection to the LDAP server with the given parameters.
    """
    server = Server(**server_params)
    try:
        return Connection(server, **connection_params, auto_bind=True)
    except LDAPBindError as e:
        _fatal_error(ERROR_CONNECT_BIND, f"Unable to authenticate ({e})")
    except LDAPSocketOpenError as e:
        _fatal_error(ERROR_CONNECT_TIMEOUT,
                     f"Unable to reach host `{server.host}` ({e})")
    except Exception as e:
        _fatal_error(ERROR_CONNECT_UNEXPECTED,
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
        _fatal_error(ERROR_CONFIG_PATH, f"Invalid path `{path}`")
    except json.decoder.JSONDecodeError as e:
        _fatal_error(ERROR_CONFIG_JSON,
                     f"Failed to parse JSON in config ({e})")
    except Exception as e:
        _fatal_error(ERROR_CONFIG_UNEXPECTED,
                     f"Unexpected error while reading config ({e})")


def _run():
    """
    Main entry point for script.
    """
    arg_parser = ArgumentParser(
        prog="Deactivate AD users in StoredSafe",
        description="""
        Deactivates all StoredSafe users that have been matched against a
        deactivated user in Active Directory.
        """,
        epilog="""
        Log level can be specified using the LOG_LEVEL environment variable
        set as ERROR, WARNING or INFO.
        """
    )
    arg_parser.add_argument('-c', '--config', required=True)
    arg_parser.add_argument('-t', '--test', action="store_true")
    args = arg_parser.parse_args()

    config = get_config(args.config)
    conn = ldap_connect(
        config['ldap']['server_parameters'],
        config['ldap']['connection_parameters']
    )
    api = storedsafe_login()

    ldap_users = []
    for search_options in config['ldap']['search']:
        ldap_users.extend(get_ldap_users(conn, **search_options))
    storedsafe_users = get_storedsafe_users(api)
    matched_users = get_matched_users(
        ldap_users, storedsafe_users, config['match'])
    deactivate_storedsafe_users(api, matched_users)


if __name__ == '__main__':
    _run()
