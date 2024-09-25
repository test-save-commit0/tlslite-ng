import unittest
from tlslite.utils.x25519 import x25519, x448, X25519_G, X448_G

class TestX25519(unittest.TestCase):
    def test_x25519(self):
        # Test vector from RFC 7748
        scalar = bytes.fromhex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4')
        u_coordinate = bytes.fromhex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')
        expected_output = bytes.fromhex('c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552')

        result = x25519(scalar, u_coordinate)
        self.assertEqual(result, expected_output)

    def test_x25519_base_point(self):
        # Test with the base point
        scalar = bytes.fromhex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4')
        expected_output = bytes.fromhex('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d')

        result = x25519(scalar, X25519_G)
        self.assertEqual(result, expected_output)

    def test_x448(self):
        # Test vector from RFC 7748
        scalar = bytes.fromhex('3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3')
        u_coordinate = bytes.fromhex('06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086')
        expected_output = bytes.fromhex('ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f')

        result = x448(scalar, u_coordinate)
        self.assertEqual(result, expected_output)

    def test_x448_base_point(self):
        # Test with the base point
        scalar = bytes.fromhex('3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3')
        expected_output = bytes.fromhex('aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38')

        result = x448(scalar, X448_G)
        self.assertEqual(result, expected_output)

if __name__ == '__main__':
    unittest.main()
