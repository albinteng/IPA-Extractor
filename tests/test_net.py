# -*- coding: utf-8 -*-
"""Downloads over https (net.py)."""

import unittest
from unittest import mock


class CertificateTests(unittest.TestCase):
    def test_bundle_is_used_when_python_has_no_certificates(self):
        import net
        empty = mock.Mock(**{'cert_store_stats.return_value': {'x509_ca': 0}})
        loaded = []

        def load(cafile):
            loaded.append(cafile)
            if cafile == net.CA_FILES[1]:
                empty.cert_store_stats.return_value = {'x509_ca': 3}
            else:
                raise OSError('missing')
        empty.load_verify_locations.side_effect = load
        with mock.patch.object(net.ssl, 'create_default_context', return_value=empty):
            self.assertIs(net.context(), empty)
        self.assertEqual(loaded[-1], net.CA_FILES[1])

    def test_default_certificates_are_enough_when_present(self):
        import net
        full = mock.Mock(**{'cert_store_stats.return_value': {'x509_ca': 100}})
        with mock.patch.object(net.ssl, 'create_default_context', return_value=full):
            net.context()
        full.load_verify_locations.assert_not_called()


if __name__ == '__main__':
    unittest.main()
