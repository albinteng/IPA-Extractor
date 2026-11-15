# -*- coding: utf-8 -*-
"""Downloads over https that also work where Python finds no certificates.

A Python from python.org on macOS ships without root certificates until its "Install Certificates" script is run, and
a program built with Nuitka carries that Python's settings to every Linux distribution, whose certificate files lie
in different places. Windows reads its own certificate store and needs none of this.
"""

import ssl
import urllib.request

# Where systems keep the bundle of root certificates: macOS and Alpine, Debian and Ubuntu, Fedora and Red Hat, openSUSE.
CA_FILES = ('/etc/ssl/cert.pem', '/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt',
            '/etc/ssl/ca-bundle.pem')


def context():
    result = ssl.create_default_context()
    if result.cert_store_stats().get('x509_ca'):
        return result
    candidates = list(CA_FILES)
    try:
        import certifi
        candidates.insert(0, certifi.where())
    except ImportError:
        pass
    for path in candidates:
        try:
            result.load_verify_locations(cafile=path)
        except (OSError, ssl.SSLError):
            continue
        if result.cert_store_stats().get('x509_ca'):
            break
    return result


def urlopen(url, timeout=None):
    return urllib.request.urlopen(url, timeout=timeout, context=context())
