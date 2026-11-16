# -*- coding: utf-8 -*-
"""Checking whether an IPA is decrypted (ipa_verify.py)."""

import unittest

from tests.support import IpaMixin, fat_macho, thin_macho


class VerifyTests(IpaMixin, unittest.TestCase):

    def test_fully_decrypted(self):
        import ipa_verify
        result = self.verify({'X': thin_macho(*self.ARM64, 0),
                              'Frameworks/F.framework/F': thin_macho(*self.ARM64, 0)})
        self.assertEqual(result.status, ipa_verify.DECRYPTED)
        self.assertEqual(len(result.files), 2)  # the PNG, plist and Java class file are not Mach-O

    def test_partial_type_lists_decrypted_archs(self):
        import ipa_verify
        fat = fat_macho(self.ARMV7 + (thin_macho(*self.ARMV7, 0, is64=False),),
                        self.ARM64 + (thin_macho(*self.ARM64, 1),))
        result = self.verify({'X': fat})
        self.assertEqual(result.type, 'partial-decrypted-armv7')
        self.assertIn('partial-decrypted-armv6-armv7', ipa_verify.all_types())
        self.assertEqual(ipa_verify.partial_type([]), ipa_verify.PARTIAL)

    def test_encrypted_extension_is_partial(self):
        import ipa_verify
        result = self.verify({'X': thin_macho(*self.ARM64, 0),
                              'PlugIns/E.appex/E': thin_macho(*self.ARM64, 1)})
        self.assertEqual(result.status, ipa_verify.PARTIAL)
        self.assertEqual([ipa_verify.describe(f) for f in result.encrypted], ['PlugIns/E.appex/E (arm64)'])

    def test_every_fat_slice_is_checked(self):
        import ipa_verify
        only_32bit = fat_macho(self.ARMV7 + (thin_macho(*self.ARMV7, 1, is64=False),),
                               self.ARM64 + (thin_macho(*self.ARM64, 0),))
        self.assertEqual(self.verify({'X': only_32bit}).status, ipa_verify.PARTIAL_32BIT)
        arm64_encrypted = fat_macho(self.ARMV7 + (thin_macho(*self.ARMV7, 0, is64=False),),
                                    self.ARM64 + (thin_macho(*self.ARM64, 1),))
        result = self.verify({'X': arm64_encrypted})
        self.assertEqual(result.status, ipa_verify.PARTIAL)
        self.assertEqual(result.encrypted[0].encrypted_archs, ['arm64'])

    def test_32bit_only_binary_is_not_partial_64bit(self):
        import ipa_verify
        # Without a decrypted arm64 slice beside it, nothing in the file runs on 64-bit devices.
        result = self.verify({'X': thin_macho(*self.ARMV7, 1, is64=False)})
        self.assertEqual(result.status, ipa_verify.PARTIAL)

    def test_reasons(self):
        import ipa_verify
        fat_32 = fat_macho(self.ARMV7 + (thin_macho(*self.ARMV7, 1, is64=False),),
                           self.ARM64 + (thin_macho(*self.ARM64, 0),))
        result = self.verify({'X': thin_macho(*self.ARM64, 1),
                              'PlugIns/E.appex/E': thin_macho(*self.ARM64, 1),
                              'Watch/W.app/PlugIns/WE.appex/WE': thin_macho(*self.ARM64, 1),
                              'Frameworks/F.framework/F': thin_macho(*self.ARM64, 1),
                              'Frameworks/libz.dylib': thin_macho(*self.ARM64, 1),
                              'Frameworks/G.framework/G': fat_32,
                              'Data/plugin.bin': thin_macho(*self.ARM64, 1),
                              'Broken': thin_macho(*self.ARM64, 0)[:40]})
        reasons = {ipa_verify.short_name(f.name): ipa_verify.reason(f) for f in result.encrypted}
        self.assertEqual(reasons, {'X': 'main', 'PlugIns/E.appex/E': 'appex',
                                   'Watch/W.app/PlugIns/WE.appex/WE': 'watch',
                                   'Frameworks/F.framework/F': 'framework', 'Frameworks/libz.dylib': 'framework',
                                   'Frameworks/G.framework/G': 'slice32', 'Data/plugin.bin': 'other',
                                   'Broken': 'unreadable'})

    def test_truncated_macho_counts_as_not_verified(self):
        import ipa_verify
        result = self.verify({'X': thin_macho(*self.ARM64, 0)[:40]})
        self.assertEqual(result.status, ipa_verify.PARTIAL)
        self.assertTrue(result.files[0].error)


if __name__ == '__main__':
    unittest.main()
