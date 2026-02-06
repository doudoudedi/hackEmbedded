"""
Database module for hackebds - SQLite-based storage for device information and exploits.
Replaces the previous /tmp/model_tree_info/ file-based storage.
"""

import sqlite3
import os
import shutil
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

try:
    import pkg_resources
except ImportError:
    pkg_resources = None


def get_db_dir() -> str:
    """Get the hackebds configuration directory path (~/.hackebds/)."""
    return os.path.join(str(Path.home()), ".hackebds")


def get_db_path() -> str:
    """Get the database file path (~/.hackebds/hackebds.db)."""
    return os.path.join(get_db_dir(), "hackebds.db")


def get_connection() -> sqlite3.Connection:
    """Get a database connection with row factory enabled."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def copy_default_database_if_needed() -> None:
    """
    Copy the default database from package resources to user directory if it doesn't exist.
    """
    db_path = get_db_path()

    # If database already exists, do nothing
    if os.path.exists(db_path):
        return

    # Ensure directory exists
    db_dir = get_db_dir()
    os.makedirs(db_dir, exist_ok=True)

    # Try to locate default database in package resources
    default_db_path = None

    # Method 1: Use pkg_resources
    if pkg_resources is not None:
        try:
            default_db_path = pkg_resources.resource_filename('hackebds', 'data/hackebds.db')
        except Exception:
            pass

    # Method 2: Fallback to local file path (for development or if pkg_resources fails)
    if default_db_path is None or not os.path.exists(default_db_path):
        # Try relative to this module
        module_dir = os.path.dirname(os.path.abspath(__file__))
        candidate = os.path.join(module_dir, 'data', 'hackebds.db')
        if os.path.exists(candidate):
            default_db_path = candidate

    if default_db_path and os.path.exists(default_db_path):
        try:
            shutil.copy2(default_db_path, db_path)
            print(f"Initialized default database at {db_path}")
        except Exception as e:
            print(f"Warning: Could not copy default database: {e}")
            # Continue with empty database - tables will be created below
    else:
        print(f"Warning: Default database not found in package resources")
        # Continue with empty database - tables will be created below


def init_db() -> None:
    """Initialize the database directory and create tables if they don't exist."""
    # Copy default database from package if it doesn't exist
    copy_default_database_if_needed()

    # Ensure directory exists (in case copy function didn't create it)
    db_dir = get_db_dir()
    os.makedirs(db_dir, exist_ok=True)

    conn = get_connection()
    cursor = conn.cursor()

    # Create devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            model_name TEXT PRIMARY KEY,
            arch TEXT,
            function TEXT,
            os TEXT,
            cpu_vendor TEXT,
            cpu_model TEXT,
            web_server TEXT,
            ssh_support TEXT,
            eavesdropping TEXT,
            telnet_user TEXT,
            telnet_passwd TEXT,
            sdk_link TEXT,
            openwrt_support TEXT,
            is_vulnerable TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create exploits table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS exploits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            description TEXT,
            poc_code TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (model_name) REFERENCES devices(model_name),
            UNIQUE(model_name, cve_id)
        )
    ''')

    # Create model-arch mapping cache table (for learning module)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_arch_cache (
            model_name TEXT PRIMARY KEY,
            arch TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create model profile table for storing complete model configurations
    # This stores arch + mcpu + endianness for quick reuse
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_profiles (
            model_name TEXT PRIMARY KEY,
            arch TEXT NOT NULL,
            mcpu TEXT,
            endianness TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create CVE online query cache table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name TEXT NOT NULL,
            cve_id TEXT,
            url TEXT,
            fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


def insert_device(model_name: str, info_list: List) -> None:
    """
    Insert or update a device in the database.

    Args:
        model_name: The device model name (primary key)
        info_list: List containing device info in order:
            [arch, function, os, cpu_vendor, cpu_model, web_server,
             ssh_support, eavesdropping, telnet_user, telnet_passwd,
             sdk_link, openwrt_support, is_vulnerable]
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Clean the list: convert to strings and skip dict values
    clean_list = []
    for item in info_list:
        if isinstance(item, dict):
            # Skip dict values (exploit data should not be in device info)
            continue
        clean_list.append(str(item) if item is not None else '')

    # Ensure we have at least 13 elements
    while len(clean_list) < 13:
        clean_list.append('')

    cursor.execute('''
        INSERT OR REPLACE INTO devices
        (model_name, arch, function, os, cpu_vendor, cpu_model, web_server,
         ssh_support, eavesdropping, telnet_user, telnet_passwd, sdk_link,
         openwrt_support, is_vulnerable, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ''', (model_name, clean_list[0], clean_list[1], clean_list[2], clean_list[3],
          clean_list[4], clean_list[5], clean_list[6], clean_list[7], clean_list[8],
          clean_list[9], clean_list[10], clean_list[11], clean_list[12]))

    conn.commit()
    conn.close()


def insert_exploit(model_name: str, cve_id: str, description: str, poc_code: str) -> None:
    """
    Insert or update an exploit/POC in the database.

    Args:
        model_name: The device model name
        cve_id: CVE ID or exploit identifier
        description: Description of the vulnerability
        poc_code: The POC/exploit code
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT OR REPLACE INTO exploits (model_name, cve_id, description, poc_code)
        VALUES (?, ?, ?, ?)
    ''', (model_name, cve_id, description, poc_code))

    conn.commit()
    conn.close()


def get_device(model_name: str) -> Optional[Dict[str, Any]]:
    """
    Get device information by model name.

    Args:
        model_name: The device model name

    Returns:
        Dictionary with device info or None if not found
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM devices WHERE model_name = ?', (model_name,))
    row = cursor.fetchone()

    conn.close()

    if row:
        return dict(row)
    return None


def get_all_devices() -> List[Dict[str, Any]]:
    """
    Get all devices from the database.

    Returns:
        List of dictionaries with device info
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM devices ORDER BY model_name')
    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_exploits(model_name: str) -> Dict[str, Tuple[str, str]]:
    """
    Get all exploits for a device.

    Args:
        model_name: The device model name

    Returns:
        Dictionary mapping cve_id to (description, poc_code) tuple
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT cve_id, description, poc_code
        FROM exploits
        WHERE model_name = ?
    ''', (model_name,))
    rows = cursor.fetchall()

    conn.close()

    result = {}
    for row in rows:
        result[row['cve_id']] = [row['description'] or '', row['poc_code'] or '']
    return result


def get_all_exploits() -> Dict[str, Dict[str, Tuple[str, str]]]:
    """
    Get all exploits grouped by model name.

    Returns:
        Dictionary mapping model_name to {cve_id: (description, poc_code)}
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT model_name, cve_id, description, poc_code FROM exploits')
    rows = cursor.fetchall()

    conn.close()

    result = {}
    for row in rows:
        model = row['model_name']
        if model not in result:
            result[model] = {}
        result[model][row['cve_id']] = [row['description'] or '', row['poc_code'] or '']
    return result


def search_devices(keyword: str) -> List[Dict[str, Any]]:
    """
    Search devices by keyword (fuzzy match on model_name).

    Args:
        keyword: Search keyword

    Returns:
        List of matching devices
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM devices
        WHERE model_name LIKE ?
        ORDER BY model_name
    ''', (f'%{keyword}%',))
    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]


def update_arch_cache(model_name: str, arch: str) -> None:
    """
    Update the model-architecture mapping cache.

    Args:
        model_name: The device model name
        arch: The architecture
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT OR REPLACE INTO model_arch_cache (model_name, arch, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', (model_name, arch))

    conn.commit()
    conn.close()


def get_arch_cache(model_name: str) -> Optional[str]:
    """
    Get architecture from cache for a model.

    Args:
        model_name: The device model name

    Returns:
        Architecture string or None if not found
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT arch FROM model_arch_cache WHERE model_name = ?', (model_name,))
    row = cursor.fetchone()

    conn.close()

    if row:
        return row['arch']
    return None


def get_all_arch_cache() -> Dict[str, str]:
    """
    Get all model-architecture mappings from cache.

    Returns:
        Dictionary mapping model_name to arch
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT model_name, arch FROM model_arch_cache')
    rows = cursor.fetchall()

    conn.close()

    return {row['model_name']: row['arch'] for row in rows}


def delete_device(model_name: str) -> None:
    """
    Delete a device and its associated exploits.

    Args:
        model_name: The device model name to delete
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('DELETE FROM exploits WHERE model_name = ?', (model_name,))
    cursor.execute('DELETE FROM devices WHERE model_name = ?', (model_name,))

    conn.commit()
    conn.close()


def device_exists(model_name: str) -> bool:
    """
    Check if a device exists in the database.

    Args:
        model_name: The device model name

    Returns:
        True if device exists, False otherwise
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT 1 FROM devices WHERE model_name = ?', (model_name,))
    result = cursor.fetchone() is not None

    conn.close()
    return result


def get_device_count() -> int:
    """
    Get the total number of devices in the database.

    Returns:
        Number of devices
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) as count FROM devices')
    result = cursor.fetchone()['count']

    conn.close()
    return result


def get_exploit_count() -> int:
    """
    Get the total number of exploits in the database.

    Returns:
        Number of exploits
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) as count FROM exploits')
    result = cursor.fetchone()['count']

    conn.close()
    return result


# CVE cache functions
def save_cve_cache(model_name: str, cve_data: List[Tuple[str, str]]) -> None:
    """
    Save CVE search results to cache.

    Args:
        model_name: The device model name searched
        cve_data: List of (cve_id, url) tuples
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Clear old cache for this model
    cursor.execute('DELETE FROM cve_cache WHERE model_name = ?', (model_name,))

    # Insert new data
    for cve_id, url in cve_data:
        cursor.execute('''
            INSERT INTO cve_cache (model_name, cve_id, url)
            VALUES (?, ?, ?)
        ''', (model_name, cve_id, url))

    conn.commit()
    conn.close()


def get_cve_cache(model_name: str) -> List[Tuple[str, str]]:
    """
    Get cached CVE search results for a model.

    Args:
        model_name: The device model name

    Returns:
        List of (cve_id, url) tuples
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT cve_id, url FROM cve_cache
        WHERE model_name = ?
        ORDER BY id
    ''', (model_name,))
    rows = cursor.fetchall()

    conn.close()

    return [(row['cve_id'], row['url']) for row in rows]


def cve_cache_exists(model_name: str) -> bool:
    """
    Check if CVE cache exists for a model.

    Args:
        model_name: The device model name

    Returns:
        True if cache exists, False otherwise
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT 1 FROM cve_cache WHERE model_name = ? LIMIT 1', (model_name,))
    result = cursor.fetchone() is not None

    conn.close()
    return result


def device_to_info_list(device: Dict[str, Any]) -> List[str]:
    """
    Convert a device dictionary to the info list format used by model_tree.

    Args:
        device: Device dictionary from database

    Returns:
        List in format [arch, function, os, cpu_vendor, cpu_model, web_server,
                       ssh_support, eavesdropping, telnet_user, telnet_passwd,
                       sdk_link, openwrt_support, is_vulnerable]
    """
    return [
        device.get('arch', ''),
        device.get('function', ''),
        device.get('os', ''),
        device.get('cpu_vendor', ''),
        device.get('cpu_model', ''),
        device.get('web_server', ''),
        device.get('ssh_support', ''),
        device.get('eavesdropping', ''),
        device.get('telnet_user', ''),
        device.get('telnet_passwd', ''),
        device.get('sdk_link', ''),
        device.get('openwrt_support', ''),
        device.get('is_vulnerable', '')
    ]


def is_database_initialized() -> bool:
    """
    Check if the database has been initialized with data.

    Returns:
        True if database has devices, False otherwise
    """
    if not os.path.exists(get_db_path()):
        return False

    return get_device_count() > 0


# Model profile functions for storing arch + mcpu + endianness
def save_model_profile(model_name: str, arch: str, mcpu: Optional[str] = None,
                       endianness: Optional[str] = None) -> None:
    """
    Save a model profile with arch, mcpu, and endianness.

    Args:
        model_name: The device model name
        arch: The architecture (e.g., 'mipsel', 'armelv7')
        mcpu: Optional CPU type (e.g., 'mips32r2', 'cortex-a7')
        endianness: Optional endianness ('little' or 'big')
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT OR REPLACE INTO model_profiles
        (model_name, arch, mcpu, endianness, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ''', (model_name, arch, mcpu, endianness))

    conn.commit()
    conn.close()


def get_model_profile(model_name: str) -> Optional[Dict[str, Any]]:
    """
    Get a model profile with arch, mcpu, and endianness.

    Args:
        model_name: The device model name

    Returns:
        Dictionary with 'arch', 'mcpu', 'endianness' or None if not found
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT arch, mcpu, endianness FROM model_profiles
        WHERE model_name = ?
    ''', (model_name,))
    row = cursor.fetchone()

    conn.close()

    if row:
        return {
            'arch': row['arch'],
            'mcpu': row['mcpu'],
            'endianness': row['endianness']
        }
    return None


def get_all_model_profiles() -> Dict[str, Dict[str, Any]]:
    """
    Get all model profiles.

    Returns:
        Dictionary mapping model_name to {'arch', 'mcpu', 'endianness'}
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT model_name, arch, mcpu, endianness FROM model_profiles')
    rows = cursor.fetchall()

    conn.close()

    return {
        row['model_name']: {
            'arch': row['arch'],
            'mcpu': row['mcpu'],
            'endianness': row['endianness']
        }
        for row in rows
    }


def delete_model_profile(model_name: str) -> None:
    """
    Delete a model profile.

    Args:
        model_name: The device model name to delete
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('DELETE FROM model_profiles WHERE model_name = ?', (model_name,))

    conn.commit()
    conn.close()


def model_profile_exists(model_name: str) -> bool:
    """
    Check if a model profile exists.

    Args:
        model_name: The device model name

    Returns:
        True if profile exists, False otherwise
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT 1 FROM model_profiles WHERE model_name = ? LIMIT 1', (model_name,))
    result = cursor.fetchone() is not None

    conn.close()
    return result
