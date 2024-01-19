from argparse import ArgumentParser

from .commands import ldap_deactivate

__author__ = "Oscar Mattsson <oscar@storedsafe.com>"
__version__ = "1.0.0"


def _run():
    arg_parser = ArgumentParser(
        prog="LDAP utilities for StoredSafe",
        description="""
        A collection of scripts that perform operations on a StoredSafe server
        based on input from an LDAP server.
        """,
        epilog="""
        Log level can be specified using the LOG_LEVEL environment variable
        set as ERROR, WARNING or INFO.
        """
    )

    subparsers = arg_parser.add_subparsers(required=True, dest='action')
    ldap_deactivate.add_subparser(subparsers)

    args = arg_parser.parse_args()
    if args.action == ldap_deactivate.SUBPARSER_ARGS['name']:
        ldap_deactivate.run(args)


if __name__ == '__main__':
    _run()
