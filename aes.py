"""AES-128 một khối 128 bit, kèm trạng thái trung gian.

Quy ước state:
    state[4*c + r] là byte ở hàng r, cột c.
    Dữ liệu được xếp vào ma trận theo cột.
"""

SBOX = tuple(bytes.fromhex("""
63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
"""))

INV_SBOX = tuple(SBOX.index(i) for i in range(256))

RCON = (
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
)


def xtime(a):
    """Nhân với 02 trong GF(2^8), modulo đa thức 0x11B."""
    correction = 0x1B if a & 0x80 else 0
    return ((a << 1) ^ correction) & 0xFF


def gf_mul(a, b):
    """Nhân hai byte trong GF(2^8)."""
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a

        a = xtime(a)
        b >>= 1

    return result


def sub_bytes(state, inverse=False):
    """Thay từng byte qua S-box thuận hoặc nghịch."""
    box = INV_SBOX if inverse else SBOX
    return [box[value] for value in state]


def shift_rows(state, inverse=False):
    """Quay trái hàng r đúng r byte; giải mã quay phải."""
    sign = -1 if inverse else 1

    return [
        state[4 * ((c + sign * r) % 4) + r]
        for c in range(4)
        for r in range(4)
    ]


def mix_columns(state, inverse=False):
    """Nhân từng cột state với ma trận trong GF(2^8)."""
    if inverse:
        matrix = (
            (14, 11, 13, 9),
            (9, 14, 11, 13),
            (13, 9, 14, 11),
            (11, 13, 9, 14),
        )
    else:
        matrix = (
            (2, 3, 1, 1),
            (1, 2, 3, 1),
            (1, 1, 2, 3),
            (3, 1, 1, 2),
        )

    result = []

    for c in range(4):
        column = state[4*c:4*c+4]

        for row in matrix:
            value = 0

            for coefficient, element in zip(row, column):
                value ^= gf_mul(coefficient, element)

            result.append(value)

    return result


def add_round_key(state, key):
    """XOR state với khóa vòng."""
    return [a ^ b for a, b in zip(state, key)]


def key_expansion(key):
    """Mở rộng khóa 16 byte thành 44 word, tương ứng 11 khóa."""
    if len(key) != 16:
        raise ValueError("Khóa AES-128 phải có đúng 16 byte.")

    words = [
        list(key[i:i+4])
        for i in range(0, 16, 4)
    ]

    steps = []

    for i in range(4, 44):
        temp = words[i-1][:]

        step = {
            "i": i,
            "previous": bytes(temp).hex().upper(),
            "w_i_minus_4": bytes(words[i-4]).hex().upper(),
        }

        if i % 4 == 0:
            # RotWord: quay trái một byte.
            temp = temp[1:] + temp[:1]
            step["RotWord"] = bytes(temp).hex().upper()

            # SubWord: thay từng byte qua S-box.
            temp = sub_bytes(temp)
            step["SubWord"] = bytes(temp).hex().upper()

            # XOR Rcon vào byte đầu.
            rcon = RCON[i//4-1]
            step["Rcon"] = f"{rcon:02X}000000"
            temp[0] ^= rcon

        step["temp"] = bytes(temp).hex().upper()

        word = [
            a ^ b
            for a, b in zip(words[i-4], temp)
        ]

        words.append(word)
        step["word"] = bytes(word).hex().upper()
        steps.append(step)

    # Ghép mỗi bốn word thành một khóa 16 byte.
    round_keys = [
        sum(words[i:i+4], [])
        for i in range(0, 44, 4)
    ]

    trace = {
        "words": [
            bytes(word).hex().upper()
            for word in words
        ],
        "steps": steps,
        "round_keys": [
            bytes(round_key).hex().upper()
            for round_key in round_keys
        ],
    }

    return round_keys, trace


def crypt_block(block, key, decrypt=False):
    """Trả về (kết quả dạng bytes, thông tin các bước)."""
    if len(block) != 16:
        raise ValueError("Khối AES phải có đúng 16 byte.")

    keys, schedule = key_expansion(key)
    state = list(block)

    trace = {
        "algorithm": "AES-128",
        "direction": "decrypt" if decrypt else "encrypt",
        "input": block.hex().upper(),
        "key": key.hex().upper(),
        "key_schedule": schedule,
        "states": [],
    }

    def record(round_index, stage):
        """Lưu state dưới dạng hex và ma trận 4×4."""
        trace["states"].append({
            "round": round_index,
            "stage": stage,
            "hex": bytes(state).hex().upper(),
            "matrix": [
                [
                    f"{state[4*c+r]:02X}"
                    for c in range(4)
                ]
                for r in range(4)
            ],
        })

    first_key = 10 if decrypt else 0

    record(first_key, "Input")
    state = add_round_key(state, keys[first_key])
    record(first_key, "AddRoundKey")

    if decrypt:
        # round trong trace giải mã là chỉ số khóa đang dùng.
        for i in range(9, -1, -1):
            state = shift_rows(state, inverse=True)
            record(i, "InvShiftRows")

            state = sub_bytes(state, inverse=True)
            record(i, "InvSubBytes")

            state = add_round_key(state, keys[i])
            record(i, "AddRoundKey")

            if i != 0:
                state = mix_columns(state, inverse=True)
                record(i, "InvMixColumns")

    else:
        for i in range(1, 11):
            state = sub_bytes(state)
            record(i, "SubBytes")

            state = shift_rows(state)
            record(i, "ShiftRows")

            # Vòng cuối không có MixColumns.
            if i != 10:
                state = mix_columns(state)
                record(i, "MixColumns")

            state = add_round_key(state, keys[i])
            record(i, "AddRoundKey")

    result = bytes(state)
    trace["output"] = result.hex().upper()

    return result, trace