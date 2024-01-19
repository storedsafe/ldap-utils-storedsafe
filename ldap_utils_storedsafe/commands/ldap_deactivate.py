"""
Deactivate StoredSafe users that match the given criteria for LDAP users
"""
from .. import utils
from argparse import _SubParsersAction
from storedsafe import StoredSafe


### SETUP ###

LOGGER = utils.get_logger("ldap_deactivate")
SUBPARSER_ARGS = {
    'name': 'deactivate',
    'help': "Deactivates StoredSafe users that match the given LDAP users.",
}


def add_subparser(subparsers: _SubParsersAction):
    deactivate_parser = subparsers.add_parser(**SUBPARSER_ARGS)
    deactivate_parser.add_argument('-c', '--config', required=True)
    deactivate_parser.add_argument('-t', '--test', action="store_true")


### SCRIPT ###

def deactivate_storedsafe_users(api: StoredSafe, users):
    """
    Unset the active flag on the provided StoredSafe user accounts.
    """
    for user in users:
        status = int(user['status']) ^ utils.BIT_ACTIVE
        LOGGER.info(f"Deactivating {user['username']} ({user['id']})")
        LOGGER.debug(
            f"User: {user['id']}, Status: {int(user['status'])} -> {status}")
        api.edit_user(user['id'], status=status)


def run(args):
    """
    Main entry point for script.
    """
    (
        (_ldap, _ldap_users),
        (storedsafe, _storedsafe_users),
        (_converted_users, matched_users),
    ) = utils.run_search(
        args.config)
    LOGGER.info(f"Matched {len(matched_users)} to be deactivated.")
    for user in matched_users:
        LOGGER.debug(f"User {user['username']} should be deactivated.")
    if not args.test:
        deactivate_storedsafe_users(storedsafe, matched_users)
