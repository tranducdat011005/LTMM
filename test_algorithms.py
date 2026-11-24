"""Kiểm thử DES và AES-128 bằng giá trị kỳ vọng cố định."""

import io
from pathlib import Path
import sys
import unittest

import aes
import des
from main import VECTORS


class CryptoTests(unittest.TestCase):
    def test_known_vectors(self):
        """Kiểm tra cả mã hóa và giải mã ba vector."""
        for vector in VECTORS:
            with self.subTest(vector=vector["name"]):
                module = (
                    des if vector["algorithm"] == "DES" else aes
                )

                plain = bytes.fromhex(vector["plaintext"])
                key = bytes.fromhex(vector["key"])
                expected = bytes.fromhex(vector["ciphertext"])

                encrypted, _ = module.crypt_block(plain, key)
                decrypted, _ = module.crypt_block(
                    expected, key, decrypt=True
                )

                self.assertEqual(encrypted, expected)
                self.assertEqual(decrypted, plain)

    def test_zero_vectors(self):
        """Vector có bản rõ và khóa toàn byte 00."""
        des_result, _ = des.crypt_block(bytes(8), bytes(8))
        aes_result, _ = aes.crypt_block(bytes(16), bytes(16))

        self.assertEqual(
            des_result.hex(),
            "8ca64de9c1b123a7",
        )
        self.assertEqual(
            aes_result.hex(),
            "66e94bd4ef8a2c3b884cfa59ca342b2e",
        )

    def test_des_round_one(self):
        """Kiểm tra các giá trị trung gian DES vòng 1."""
        _, trace = des.crypt_block(
            bytes.fromhex("0123456789ABCDEF"),
            bytes.fromhex("133457799BBCDFF1"),
        )

        self.assertEqual(
            trace["IP"], "CC00CCFFF0AAF0AA"
        )
        self.assertEqual(
            trace["key_schedule"]["C0"], "F0CCAAF"
        )
        self.assertEqual(
            trace["key_schedule"]["D0"], "556678F"
        )

        expected = {
            "K": "1B02EFFC7072",
            "E": "7A15557A1555",
            "xor_key": "6117BA866527",
            "S": "5C82B597",
            "P": "234AA9BB",
            "L": "F0AAF0AA",
            "R": "EF4A6544",
        }

        for field, value in expected.items():
            with self.subTest(field=field):
                self.assertEqual(
                    trace["rounds"][0][field], value
                )

        self.assertEqual(
            trace["preoutput"], "0A4CD99543423234"
        )

    def test_des_decryption_key_order(self):
        """Giải mã phải dùng K16 trước và K1 cuối."""
        _, trace = des.crypt_block(
            bytes.fromhex("85E813540F0AB405"),
            bytes.fromhex("133457799BBCDFF1"),
            decrypt=True,
        )

        indices = [
            row["key_index"]
            for row in trace["rounds"]
        ]

        self.assertEqual(indices, list(range(16, 0, -1)))

    def test_des_parity(self):
        """Đổi các bit parity không làm đổi khóa vòng."""
        key = bytes.fromhex("133457799BBCDFF1")
        changed_parity = bytes(value ^ 1 for value in key)

        self.assertEqual(
            des.key_schedule(key)[0],
            des.key_schedule(changed_parity)[0],
        )

    def test_aes_round_one(self):
        """Kiểm tra từng phép biến đổi AES vòng 1."""
        _, trace = aes.crypt_block(
            bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
            bytes.fromhex("000102030405060708090A0B0C0D0E0F"),
        )

        states = {
            (step["round"], step["stage"]): step["hex"]
            for step in trace["states"]
        }

        expected = {
            (0, "AddRoundKey"):
                "00102030405060708090A0B0C0D0E0F0",
            (1, "SubBytes"):
                "63CAB7040953D051CD60E0E7BA70E18C",
            (1, "ShiftRows"):
                "6353E08C0960E104CD70B751BACAD0E7",
            (1, "MixColumns"):
                "5F72641557F5BC92F7BE3B291DB9F91A",
            (1, "AddRoundKey"):
                "89D810E8855ACE682D1843D8CB128FE4",
        }

        for step, value in expected.items():
            with self.subTest(step=step):
                self.assertEqual(states[step], value)

        keys = trace["key_schedule"]["round_keys"]

        self.assertEqual(
            keys[1],
            "D6AA74FDD2AF72FADAA678F1D6AB76FE",
        )
        self.assertEqual(
            keys[10],
            "13111D7FE3944A17F307A78B4D2B30C5",
        )

    def test_aes_field(self):
        """Kiểm tra phép nhân GF và một cột MixColumns."""
        self.assertEqual(aes.gf_mul(0x57, 0x83), 0xC1)
        self.assertEqual(aes.xtime(0x80), 0x1B)
        self.assertEqual(aes.RCON[7], 0x80)

        state = [0xD4, 0xBF, 0x5D, 0x30] * 4

        self.assertEqual(
            aes.mix_columns(state)[:4],
            [0x04, 0x66, 0x81, 0xE5],
        )

    def test_aes_inverse_operations(self):
        """Kiểm tra S-box và các phép biến đổi nghịch."""
        values = list(range(256))

        self.assertEqual(
            aes.sub_bytes(aes.sub_bytes(values), inverse=True),
            values,
        )

        # Kiểm tra các vector cơ sở của state 128 bit.
        for bit in range(128):
            state = list((1 << bit).to_bytes(16, "big"))

            self.assertEqual(
                aes.shift_rows(
                    aes.shift_rows(state), inverse=True
                ),
                state,
            )

            self.assertEqual(
                aes.mix_columns(
                    aes.mix_columns(state), inverse=True
                ),
                state,
            )

    def test_aes_last_round(self):
        """Vòng mã hóa cuối không có MixColumns."""
        _, trace = aes.crypt_block(bytes(16), bytes(16))

        last_round = [
            step["stage"]
            for step in trace["states"]
            if step["round"] == 10
        ]

        self.assertEqual(
            last_round,
            ["SubBytes", "ShiftRows", "AddRoundKey"],
        )

        # Input + AddRoundKey đầu + 9*4 bước + 3 bước cuối.
        self.assertEqual(len(trace["states"]), 41)

    def test_invalid_lengths(self):
        """Từ chối khóa hoặc khối sai kích thước."""
        for module, size in ((des, 8), (aes, 16)):
            for bad_size in (0, size - 1, size + 1):
                with self.subTest(
                    algorithm=module.__name__,
                    length=bad_size,
                ):
                    with self.assertRaises(ValueError):
                        module.crypt_block(
                            bytes(bad_size), bytes(size)
                        )

                    with self.assertRaises(ValueError):
                        module.crypt_block(
                            bytes(size), bytes(bad_size)
                        )


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        CryptoTests
    )

    buffer = io.StringIO()
    runner = unittest.TextTestRunner(
        stream=buffer,
        verbosity=2,
    )

    result = runner.run(suite)
    report = buffer.getvalue()

    print(report, end="")

    output = Path(__file__).resolve().parent / "results"
    output.mkdir(parents=True, exist_ok=True)

    (output / "test_run.txt").write_text(
        report, encoding="utf-8"
    )

    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()