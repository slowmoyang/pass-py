#!/usr/bin/env python3
import os
import shutil
import argparse
from argparse import BooleanOptionalAction
from pathlib import Path
from subprocess import Popen, PIPE
import getpass
import json
from dataclasses import dataclass, asdict
import pyperclip


CONFIG_PATH = Path(
    os.getenv(
        key='PASS_PY_CONFIG',
        default=(Path.home() / '.pass-py.json'))
)


@dataclass
class Config:
    user: str
    gpg: str
    store: Path

    @classmethod
    def from_json(cls, path: Path = CONFIG_PATH) -> 'Config':
        with open(path) as stream:
            config = json.load(stream)
        config['store'] = Path(config['store'])
        return cls(**config)

    def to_json(self, path: Path) -> None:
        config = asdict(self)
        config['store'] = str(config['store'])

        if path.exists():
            backup_path = path.with_suffix('.json.bak')
            print(f'Create a backup of the existing config file:'
                  f'{path} --> {backup_path}')
            path.rename(backup_path)

        with open(path, 'w') as stream:
            json.dump(config, stream, indent=2)


def init_config(gpg: str, user: str, store: Path) -> None:
    if not store.exists():
        print(f'created directory {store}')
        store.mkdir(parents=True)
    config = Config(user=user, store=store, gpg=gpg)
    config.to_json(CONFIG_PATH)


def print_config() -> None:
    """docstirng for list_passwords
    """
    config = Config.from_json()
    gpg_status = "[NOT FOUND] " if shutil.which(config.gpg) is None else ""
    store_status = "[NOT FOUND] " if not config.store.exists() else ""
    print(f'{gpg_status}gpg: {shutil.which(config.gpg)}')
    print(f'{store_status}store: {str(config.store):s}')
    print(f'user: {config.user:s}')


def list_passwords() -> None:
    """docstirng for list_passwords
    """
    config = Config.from_json()
    for gpg_file in config.store.glob('**/*.gpg'):
        pass_id = str(gpg_file.relative_to(config.store).with_suffix(''))
        print(pass_id)


def get_password(password: str, copy: bool):
    """docstirng for get_password

    :password: TODO
    :copy: TODO

    """
    config = Config.from_json()
    gpg_file = config.store / password
    gpg_file = gpg_file.with_suffix('.gpg')
    if not gpg_file.exists():
        raise FileNotFoundError(gpg_file)

    # FIXME environment variable
    args = [
        config.gpg,
        '-d',
        '--pinentry-mode',
        'loopback',
        str(gpg_file),
    ]

    with Popen(args,
               shell=False,
               stdin=PIPE,
               stdout=PIPE,
               stderr=PIPE,
               startupinfo=None,
               env=None
               ) as proc:
        password = proc.stdout.read() # type: ignore
    password = password.decode('utf-8').strip() # type: ignore

    if copy:
        pyperclip.copy(password)
    else:
        print(password)


class PasswordConfirmationFailureError(Exception):
    def __init__(self):
        super().__init__("Error: the entered passwords do not match.")


def insert_password(name):
    """docstirng for insert_password

    :password: TODO
    :copy: TODO

    """
    config = Config.from_json()

    password = getpass.getpass(prompt=f'Enter password for {name}: ')
    password_check = getpass.getpass(prompt=f'Retype password for {name}: ')
    if password != password_check:
        raise PasswordConfirmationFailureError()

    gpg_path = Path(config.store) / name
    if not gpg_path.parent.exists():
        gpg_path.parent.mkdir(parents=True)

    args = [
        config.gpg,
        '--encrypt',
        '--recipient', config.user, # FIXME
        '--output', str(gpg_path.with_suffix('.gpg')),
        '--pinentry-mode', 'loopback',
    ]

    password = bytes(password, 'utf-8')
    with Popen(args,
               shell=False,
               stdin=PIPE,
               stdout=PIPE,
               stderr=PIPE,
               startupinfo=None,
               env=None
               ) as proc:
        proc.communicate(input=password)


# TODO add xkcd
# TODO openssl
# def generate_password():


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    subparsers = parser.add_subparsers(required=True)

    ###########################################################################
    # init config
    ###########################################################################
    init_parser = subparsers.add_parser('init', help='initialise config')
    init_parser.set_defaults(func=init_config)
    init_parser.add_argument('--user', type=str, required=True,
                             help='gpg user id')
    init_parser.add_argument('--gpg', type=str, default='gpg',
                             help='gpg cmd')
    init_parser.add_argument('--store', type=Path,
                             default=Path.home() / '.password-store')
    ###########################################################################
    # get config
    ###########################################################################
    config_parser = subparsers.add_parser('config', aliases=['c'],
                                          help='print config')
    config_parser.set_defaults(func=print_config)

    ###########################################################################
    # get a password
    ###########################################################################
    get_parser = subparsers.add_parser('get', aliases=['g'],
                                       help='get password')
    get_parser.set_defaults(func=get_password)

    get_parser.add_argument('password')
    get_parser.add_argument("-c", "--copy", action=BooleanOptionalAction,
                            default=False,
                            help="copy a password to clipboard")

    ###########################################################################
    # list passwords
    ###########################################################################
    list_parser = subparsers.add_parser('list', aliases=['ls', 'l'],
                                        help='list passwords')
    list_parser.set_defaults(func=list_passwords)

    ###########################################################################
    # insert a password
    ###########################################################################
    insert_parser = subparsers.add_parser('insert', aliases=['i'],
                                          help='insert password')
    insert_parser.add_argument('name', type=str, help='password name')
    insert_parser.set_defaults(func=insert_password)

    ###########################################################################
    # TODO generate
    ###########################################################################

    ###########################################################################
    # help
    ###########################################################################
    help_parser = subparsers.add_parser('help', aliases=['h'])
    help_parser.set_defaults(func=parser.print_help)

    ###########################################################################
    # Run!
    ###########################################################################
    args = parser.parse_args()
    args = vars(args)
    func = args.pop('func')
    func(**args)


if __name__ == "__main__":
    main()
