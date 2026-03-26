"""Common configure functions for Keychain on ArcOS"""

import logging

from unicon.core.errors import SubCommandFailure

log = logging.getLogger(__name__)


def configure_keychain(device, name, keys=None, tolerance=None):
    """Configure a keychain with optional key entries.

    Creates a keychain and optionally populates it with key entries.
    Each key entry can specify secret-key, crypto-algorithm, and
    send-lifetime settings.

    Args:
        device (obj): Device object.
        name (str): Keychain name (e.g., 'isis-key').
        keys (dict, optional): Dictionary of key entries keyed by key_id.
            Each entry is a dict with optional fields:
            - secret_key (str): Password/passphrase
            - crypto_algorithm (str): e.g., 'HMAC_SHA_1', 'HMAC_SHA_256'
            - send_lifetime_always (bool): Permanent validity
            - send_lifetime_start_time (str): Start in CCYY-MM-DDTHH:MM:SS
            - send_lifetime_end_time (str): End in CCYY-MM-DDTHH:MM:SS
        tolerance (int, optional): Receive tolerance in seconds.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure keychain

    Example:
        >>> configure_keychain(device, 'isis-key', keys={
        ...     10: {'secret_key': 'MyPass', 'crypto_algorithm': 'HMAC_SHA_1',
        ...          'send_lifetime_always': True}
        ... })
    """
    log.info(f"Configuring keychain '{name}' on {device.name}")

    config = [f'keychain {name}']

    if tolerance is not None:
        config.append(f'tolerance {tolerance}')

    if keys:
        for key_id in sorted(keys.keys(), key=lambda k: int(k)):
            entry = keys[key_id]
            if not isinstance(entry, dict):
                continue
            config.append(f'key {key_id}')

            secret = entry.get('secret_key')
            if secret is not None:
                config.append(f'secret-key {secret}')

            algo = entry.get('crypto_algorithm')
            if algo is not None:
                config.append(f'crypto-algorithm {algo}')

            always = entry.get('send_lifetime_always')
            if always is not None:
                val = 'true' if always else 'false'
                config.append(f'send-lifetime always {val}')

            start = entry.get('send_lifetime_start_time')
            if start is not None:
                config.append(f'send-lifetime start-time {start}')

            end = entry.get('send_lifetime_end_time')
            if end is not None:
                config.append(f'send-lifetime end-time {end}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure keychain '{name}' on {device.name}. "
            f"Error:\n{e}"
        )


def unconfigure_keychain(device, name):
    """Remove a keychain.

    Args:
        device (obj): Device object.
        name (str): Keychain name to remove.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove keychain

    Example:
        >>> unconfigure_keychain(device, 'isis-key')
    """
    log.info(f"Removing keychain '{name}' from {device.name}")

    config = [
        f'no keychain {name}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove keychain '{name}' from {device.name}. "
            f"Error:\n{e}"
        )


def configure_keychain_key(device, keychain_name, key_id,
                           secret_key=None, crypto_algorithm=None,
                           send_lifetime_always=None,
                           send_lifetime_start_time=None,
                           send_lifetime_end_time=None):
    """Add or update a single key entry in a keychain.

    Args:
        device (obj): Device object.
        keychain_name (str): Keychain name.
        key_id (int): Key ID.
        secret_key (str, optional): Password/passphrase.
        crypto_algorithm (str, optional): Algorithm (e.g., 'HMAC_SHA_1').
        send_lifetime_always (bool, optional): Permanent validity.
        send_lifetime_start_time (str, optional): Start time.
        send_lifetime_end_time (str, optional): End time.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to configure keychain key

    Example:
        >>> configure_keychain_key(device, 'isis-key', 10,
        ...     secret_key='MyPass', crypto_algorithm='HMAC_SHA_1',
        ...     send_lifetime_always=True)
    """
    log.info(
        f"Configuring key {key_id} in keychain '{keychain_name}' "
        f"on {device.name}"
    )

    config = [
        f'keychain {keychain_name}',
        f'key {key_id}',
    ]

    if secret_key is not None:
        config.append(f'secret-key {secret_key}')

    if crypto_algorithm is not None:
        config.append(f'crypto-algorithm {crypto_algorithm}')

    if send_lifetime_always is not None:
        val = 'true' if send_lifetime_always else 'false'
        config.append(f'send-lifetime always {val}')

    if send_lifetime_start_time is not None:
        config.append(f'send-lifetime start-time {send_lifetime_start_time}')

    if send_lifetime_end_time is not None:
        config.append(f'send-lifetime end-time {send_lifetime_end_time}')

    config.append('!')

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not configure key {key_id} in keychain "
            f"'{keychain_name}' on {device.name}. Error:\n{e}"
        )


def unconfigure_keychain_key(device, keychain_name, key_id):
    """Remove a single key entry from a keychain.

    Args:
        device (obj): Device object.
        keychain_name (str): Keychain name.
        key_id (int): Key ID to remove.

    Returns:
        None

    Raises:
        SubCommandFailure: Failed to remove keychain key

    Example:
        >>> unconfigure_keychain_key(device, 'isis-key', 10)
    """
    log.info(
        f"Removing key {key_id} from keychain '{keychain_name}' "
        f"on {device.name}"
    )

    config = [
        f'keychain {keychain_name}',
        f'no key {key_id}',
        '!',
    ]

    try:
        device.configure(config)
    except SubCommandFailure as e:
        raise SubCommandFailure(
            f"Could not remove key {key_id} from keychain "
            f"'{keychain_name}' on {device.name}. Error:\n{e}"
        )
