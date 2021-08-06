import os
import unittest
from authlib.jose import errors
from authlib.jose import OctKey, OKPKey
from authlib.jose import JsonWebEncryption
from authlib.common.encoding import urlsafe_b64encode
from tests.util import read_file_path


class JWETest(unittest.TestCase):
    def test_not_enough_segments(self):
        s = 'a.b.c'
        jwe = JsonWebEncryption()
        self.assertRaises(
            errors.DecodeError,
            jwe.deserialize_compact,
            s, None
        )

    def test_invalid_header(self):
        jwe = JsonWebEncryption()
        public_key = read_file_path('rsa_public.pem')
        self.assertRaises(
            errors.MissingAlgorithmError,
            jwe.serialize_compact, {}, 'a', public_key
        )
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            jwe.serialize_compact, {'alg': 'invalid'}, 'a', public_key
        )
        self.assertRaises(
            errors.MissingEncryptionAlgorithmError,
            jwe.serialize_compact, {'alg': 'RSA-OAEP'}, 'a', public_key
        )
        self.assertRaises(
            errors.UnsupportedEncryptionAlgorithmError,
            jwe.serialize_compact, {'alg': 'RSA-OAEP', 'enc': 'invalid'},
            'a', public_key
        )
        self.assertRaises(
            errors.UnsupportedCompressionAlgorithmError,
            jwe.serialize_compact,
            {'alg': 'RSA-OAEP', 'enc': 'A256GCM', 'zip': 'invalid'},
            'a', public_key
        )

    def test_not_supported_alg(self):
        public_key = read_file_path('rsa_public.pem')
        private_key = read_file_path('rsa_private.pem')

        jwe = JsonWebEncryption()
        s = jwe.serialize_compact(
            {'alg': 'RSA-OAEP', 'enc': 'A256GCM'},
            'hello', public_key
        )

        jwe = JsonWebEncryption(algorithms=['RSA1_5', 'A256GCM'])
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            jwe.serialize_compact,
            {'alg': 'RSA-OAEP', 'enc': 'A256GCM'},
            'hello', public_key
        )
        self.assertRaises(
            errors.UnsupportedCompressionAlgorithmError,
            jwe.serialize_compact,
            {'alg': 'RSA1_5', 'enc': 'A256GCM', 'zip': 'DEF'},
            'hello', public_key
        )
        self.assertRaises(
            errors.UnsupportedAlgorithmError,
            jwe.deserialize_compact,
            s, private_key,
        )

        jwe = JsonWebEncryption(algorithms=['RSA-OAEP', 'A192GCM'])
        self.assertRaises(
            errors.UnsupportedEncryptionAlgorithmError,
            jwe.serialize_compact,
            {'alg': 'RSA-OAEP', 'enc': 'A256GCM'},
            'hello', public_key
        )
        self.assertRaises(
            errors.UnsupportedCompressionAlgorithmError,
            jwe.serialize_compact,
            {'alg': 'RSA-OAEP', 'enc': 'A192GCM', 'zip': 'DEF'},
            'hello', public_key
        )
        self.assertRaises(
            errors.UnsupportedEncryptionAlgorithmError,
            jwe.deserialize_compact,
            s, private_key,
        )

    def test_compact_rsa(self):
        jwe = JsonWebEncryption()
        s = jwe.serialize_compact(
            {'alg': 'RSA-OAEP', 'enc': 'A256GCM'},
            'hello',
            read_file_path('rsa_public.pem')
        )
        data = jwe.deserialize_compact(s, read_file_path('rsa_private.pem'))
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'RSA-OAEP')

    def test_with_zip_header(self):
        jwe = JsonWebEncryption()
        s = jwe.serialize_compact(
            {'alg': 'RSA-OAEP', 'enc': 'A128CBC-HS256', 'zip': 'DEF'},
            'hello',
            read_file_path('rsa_public.pem')
        )
        data = jwe.deserialize_compact(s, read_file_path('rsa_private.pem'))
        header, payload = data['header'], data['payload']
        self.assertEqual(payload, b'hello')
        self.assertEqual(header['alg'], 'RSA-OAEP')

    def test_aes_jwe(self):
        jwe = JsonWebEncryption()
        sizes = [128, 192, 256]
        _enc_choices = [
            'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
            'A128GCM', 'A192GCM', 'A256GCM'
        ]
        for s in sizes:
            alg = 'A{}KW'.format(s)
            key = os.urandom(s // 8)
            for enc in _enc_choices:
                protected = {'alg': alg, 'enc': enc}
                data = jwe.serialize_compact(protected, b'hello', key)
                rv = jwe.deserialize_compact(data, key)
                self.assertEqual(rv['payload'], b'hello')

    def test_ase_jwe_invalid_key(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'A128KW', 'enc': 'A128GCM'}
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', b'invalid-key'
        )

    def test_aes_gcm_jwe(self):
        jwe = JsonWebEncryption()
        sizes = [128, 192, 256]
        _enc_choices = [
            'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
            'A128GCM', 'A192GCM', 'A256GCM'
        ]
        for s in sizes:
            alg = 'A{}GCMKW'.format(s)
            key = os.urandom(s // 8)
            for enc in _enc_choices:
                protected = {'alg': alg, 'enc': enc}
                data = jwe.serialize_compact(protected, b'hello', key)
                rv = jwe.deserialize_compact(data, key)
                self.assertEqual(rv['payload'], b'hello')

    def test_ase_gcm_jwe_invalid_key(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'A128GCMKW', 'enc': 'A128GCM'}
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', b'invalid-key'
        )

    def test_ecdh_es_key_agreement_computation(self):
        # https://tools.ietf.org/html/rfc7518#appendix-C
        alice_ephemeral_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        }
        bob_static_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }
        headers = {
            "alg": "ECDH-ES",
            "enc": "A128GCM",
            "apu": "QWxpY2U",
            "apv": "Qm9i"
        }

        alg = JsonWebEncryption.ALG_REGISTRY['ECDH-ES']

        alice_ephemeral_key = alg.prepare_key(alice_ephemeral_key)
        bob_static_key = alg.prepare_key(bob_static_key)

        alice_ephemeral_pubkey = alice_ephemeral_key.get_op_key('wrapKey')
        bob_static_pubkey = bob_static_key.get_op_key('wrapKey')

        dk_at_alice = alg.deliver(alice_ephemeral_key, bob_static_pubkey, headers, 128)
        self.assertEqual(urlsafe_b64encode(dk_at_alice), b'VqqN6vgjbSBcIijNcacQGg')

        dk_at_bob = alg.deliver(bob_static_key, alice_ephemeral_pubkey, headers, 128)
        self.assertEqual(urlsafe_b64encode(dk_at_bob), b'VqqN6vgjbSBcIijNcacQGg')

    def test_ecdh_es_jwe(self):
        jwe = JsonWebEncryption()
        key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }
        for alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]:
            protected = {'alg': alg, 'enc': 'A128GCM'}
            data = jwe.serialize_compact(protected, b'hello', key)
            rv = jwe.deserialize_compact(data, key)
            self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_es_jwe_with_okp(self):
        jwe = JsonWebEncryption()
        key = OKPKey.generate_key('X25519', is_private=True)
        for alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]:
            protected = {'alg': alg, 'enc': 'A128GCM'}
            data = jwe.serialize_compact(protected, b'hello', key)
            rv = jwe.deserialize_compact(data, key)
            self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_es_decryption_with_public_key_fails(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-ES', 'enc': 'A128GCM'}

        key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        }
        data = jwe.serialize_compact(protected, b'hello', key)
        self.assertRaises(
            ValueError,
            jwe.deserialize_compact,
            data, key
        )

    def test_ecdh_es_encryption_fails_if_key_curve_inappropriate(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-ES', 'enc': 'A128GCM'}

        key = OKPKey.generate_key('Ed25519', is_private=True)
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', key
        )

    def test_ecdh_1pu_key_agreement_computation(self):
        # https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#appendix-A
        alice_static_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            "d": "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"
        }
        bob_static_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }
        alice_ephemeral_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        }
        headers = {
            "alg": "ECDH-1PU",
            "enc": "A256GCM",
            "apu": "QWxpY2U",
            "apv": "Qm9i"
        }

        alg = JsonWebEncryption.ALG_REGISTRY['ECDH-1PU']

        alice_static_key = alg.prepare_key(alice_static_key)
        bob_static_key = alg.prepare_key(bob_static_key)
        alice_ephemeral_key = alg.prepare_key(alice_ephemeral_key)

        alice_static_pubkey = alice_static_key.get_op_key('wrapKey')
        bob_static_pubkey = bob_static_key.get_op_key('wrapKey')
        alice_ephemeral_pubkey = alice_ephemeral_key.get_op_key('wrapKey')

        dk_at_alice = alg.deliver_at_sender(alice_static_key, alice_ephemeral_key, bob_static_pubkey, headers, 256, None)
        self.assertEqual(urlsafe_b64encode(dk_at_alice), b'bK8Tcj0UhQrUtCzW3ek1v_0v_wCpunDeBcIDpeFyLKc')

        dk_at_bob = alg.deliver_at_recipient(bob_static_key, alice_static_pubkey, alice_ephemeral_pubkey, headers, 256, None)
        self.assertEqual(urlsafe_b64encode(dk_at_bob), b'bK8Tcj0UhQrUtCzW3ek1v_0v_wCpunDeBcIDpeFyLKc')

    def test_ecdh_1pu_jwe(self):
        jwe = JsonWebEncryption()
        alice_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            "d": "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"
        }
        bob_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }
        for alg, enc in [
            ('ECDH-1PU', 'A256GCM'),
            ('ECDH-1PU+A128KW', 'A256CBC-HS512'),
            ('ECDH-1PU+A192KW', 'A256CBC-HS512'),
            ('ECDH-1PU+A256KW', 'A256CBC-HS512'),
        ]:
            protected = {'alg': alg, 'enc': enc}
            data = jwe.serialize_compact(protected, b'hello', bob_key, sender_key=alice_key)
            rv = jwe.deserialize_compact(data, bob_key, sender_key=alice_key)
            self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_1pu_jwe_with_okp(self):
        jwe = JsonWebEncryption()
        alice_key = OKPKey.generate_key('X25519', is_private=True)
        bob_key = OKPKey.generate_key('X25519', is_private=True)
        for alg, enc in [
            ('ECDH-1PU', 'A256GCM'),
            ('ECDH-1PU+A128KW', 'A256CBC-HS512'),
            ('ECDH-1PU+A192KW', 'A256CBC-HS512'),
            ('ECDH-1PU+A256KW', 'A256CBC-HS512'),
        ]:
            protected = {'alg': alg, 'enc': enc}
            data = jwe.serialize_compact(protected, b'hello', bob_key, sender_key=alice_key)
            rv = jwe.deserialize_compact(data, bob_key, sender_key=alice_key)
            self.assertEqual(rv['payload'], b'hello')

    def test_ecdh_1pu_encryption_with_public_sender_key_fails(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-1PU', 'enc': 'A256GCM'}

        alice_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        }
        bob_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }
        self.assertRaises(
            ValueError,
            jwe.serialize_compact, protected,
            b'hello', bob_key, sender_key=alice_key
        )

    def test_ecdh_1pu_decryption_with_public_recipient_key_fails(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-1PU', 'enc': 'A256GCM'}

        alice_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            "d": "Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"
        }
        bob_key = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"
        }
        data = jwe.serialize_compact(protected, b'hello', bob_key, sender_key=alice_key)
        self.assertRaises(
            ValueError,
            jwe.deserialize_compact,
            data, bob_key, sender_key=alice_key
        )

    def test_ecdh_1pu_encryption_fails_if_keys_curve_inappropriate(self):
        jwe = JsonWebEncryption()
        protected = {'alg': 'ECDH-1PU', 'enc': 'A256GCM'}

        alice_key = OKPKey.generate_key('Ed25519', is_private=True)
        bob_key = OKPKey.generate_key('Ed25519', is_private=True)
        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', bob_key, sender_key=alice_key
        )

    def test_dir_alg(self):
        jwe = JsonWebEncryption()
        key = OctKey.generate_key(128, is_private=True)
        protected = {'alg': 'dir', 'enc': 'A128GCM'}
        data = jwe.serialize_compact(protected, b'hello', key)
        rv = jwe.deserialize_compact(data, key)
        self.assertEqual(rv['payload'], b'hello')

        key2 = OctKey.generate_key(256, is_private=True)
        self.assertRaises(ValueError, jwe.deserialize_compact, data, key2)

        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', key2
        )

    def test_dir_alg_c20p(self):
        jwe = JsonWebEncryption()
        key = OctKey.generate_key(256, is_private=True)
        protected = {'alg': 'dir', 'enc': 'C20P'}
        data = jwe.serialize_compact(protected, b'hello', key)
        rv = jwe.deserialize_compact(data, key)
        self.assertEqual(rv['payload'], b'hello')

        key2 = OctKey.generate_key(128, is_private=True)
        self.assertRaises(ValueError, jwe.deserialize_compact, data, key2)

        self.assertRaises(
            ValueError,
            jwe.serialize_compact,
            protected, b'hello', key2
        )
