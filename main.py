"""Chạy các test vector DES/AES và lưu trạng thái trung gian."""

from pathlib import Path

import aes
import des


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"

# Các số dưới đây là hex, không phải chuỗi ASCII.
VECTORS = [
    {
        "name": "des_classic",
        "algorithm": "DES",
        "plaintext": "0123456789ABCDEF",
        "key": "133457799BBCDFF1",
        "ciphertext": "85E813540F0AB405",
        "source": (
            "tong-hop-tai-lieu-cuoi-ky-math-101-gcd-modular-"
            "arithmetic-cryptography.pdf, trang PDF 10-17"
        ),
    },
    {
        "name": "aes_class_example",
        "algorithm": "AES-128",
        "plaintext": "3243F6A8885A308D313198A2E0370734",
        "key": "2B7E151628AED2A6ABF7158809CF4F3C",
        "ciphertext": "3925841D02DC09FBDC118597196A0B32",
        "source": (
            "tom-tat-ly-thuyet-mat-ma-ma-co-dien-va-hien-dai.pdf, "
            "trang PDF 20-25; FIPS 197 (2001), Appendix B"
        ),
    },
    {
        "name": "aes_fips197",
        "algorithm": "AES-128",
        "plaintext": "00112233445566778899AABBCCDDEEFF",
        "key": "000102030405060708090A0B0C0D0E0F",
        "ciphertext": "69C4E0D86A7B0430D8CDB78070B4C55A",
        "source": "FIPS 197 (2001), Appendix C.1",
    },
]


def render_des(trace):
    """Chuyển trace DES thành báo cáo dễ đọc."""
    lines = [
        f"DES / {trace['direction']}",
        f"Input: {trace['input']}",
        f"Key:   {trace['key']}",
        "",
        "KEY SCHEDULE",
    ]

    schedule = trace["key_schedule"]

    lines.append(f"PC1 = {schedule['PC1']}")
    lines.append(f"C0  = {schedule['C0']}")
    lines.append(f"D0  = {schedule['D0']}")

    for row in schedule["rounds"]:
        lines.append(
            f"K{row['round']:02}: "
            f"shift={row['shift']} "
            f"C={row['C']} "
            f"D={row['D']} "
            f"K={row['K']}"
        )

    lines.extend([
        "",
        f"IP = {trace['IP']}",
        f"L0 = {trace['L0']}",
        f"R0 = {trace['R0']}",
    ])

    for row in trace["rounds"]:
        lines.append(
            f"\nROUND {row['round']:02} "
            f"(using K{row['key_index']:02}={row['K']})"
        )

        for field in ("L_in", "R_in", "E", "xor_key"):
            lines.append(f"  {field} = {row[field]}")

        for box in row["S_boxes"]:
            lines.append(
                f"  S{box['box']}: "
                f"bits={box['input_bits']} "
                f"row={box['row']} "
                f"column={box['column']} "
                f"output={box['output']}"
            )

        for field in ("S", "P", "L", "R"):
            lines.append(f"  {field} = {row[field]}")

    lines.append(f"\nR16 || L16 = {trace['preoutput']}")
    lines.append(f"Output = {trace['output']}")

    return "\n".join(lines) + "\n"


def render_aes(trace):
    """Chuyển trace AES thành báo cáo có ma trận từng bước."""
    lines = [
        f"AES-128 / {trace['direction']}",
        f"Input: {trace['input']}",
        f"Key:   {trace['key']}",
        "",
        "KEY EXPANSION",
    ]

    schedule = trace["key_schedule"]

    for i, word in enumerate(schedule["words"][:4]):
        lines.append(f"w[{i:02}] = {word}")

    for step in schedule["steps"]:
        lines.append(f"\nGenerate w[{step['i']:02}]")

        for field in (
            "previous",
            "RotWord",
            "SubWord",
            "Rcon",
            "temp",
            "w_i_minus_4",
            "word",
        ):
            if field in step:
                lines.append(f"  {field} = {step[field]}")

    lines.append("\nROUND KEYS")

    for i, key in enumerate(schedule["round_keys"]):
        lines.append(f"K{i:02} = {key}")

    lines.extend([
        "",
        "STATES",
        "Hex strings: read column by column.",
        "Matrices below: displayed row by row.",
        "For decryption, round/key-index decreases from 10 to 0.",
    ])

    for step in trace["states"]:
        lines.append(
            f"\nRound/key-index {step['round']:02} "
            f"- {step['stage']}"
        )
        lines.append(f"  HEX = {step['hex']}")

        for row in step["matrix"]:
            lines.append("  " + " ".join(row))

    lines.append(f"\nOutput = {trace['output']}")

    return "\n".join(lines) + "\n"


def run_vector(vector):
    """Chạy một vector, kiểm định và lưu cả hai chiều."""
    module = des if vector["algorithm"] == "DES" else aes
    renderer = render_des if module is des else render_aes

    plain = bytes.fromhex(vector["plaintext"])
    key = bytes.fromhex(vector["key"])
    expected = bytes.fromhex(vector["ciphertext"])

    encrypted, encrypt_trace = module.crypt_block(plain, key)

    # Giải mã bản mã kỳ vọng độc lập.
    decrypted, decrypt_trace = module.crypt_block(
        expected, key, decrypt=True
    )

    if encrypted != expected:
        raise RuntimeError(
            f"{vector['name']}: encryption FAILED; "
            f"expected {expected.hex().upper()}, "
            f"got {encrypted.hex().upper()}"
        )

    if decrypted != plain:
        raise RuntimeError(
            f"{vector['name']}: decryption FAILED"
        )

    for direction, trace in (
        ("encrypt", encrypt_trace),
        ("decrypt", decrypt_trace),
    ):
        report = (
            f"Vector: {vector['name']}\n"
            f"Source: {vector['source']}\n\n"
            + renderer(trace)
        )

        path = RESULTS / f"{vector['name']}_{direction}.txt"
        path.write_text(report, encoding="utf-8")

        print(report)

    return (
        f"PASS {vector['name']}\n"
        f"  P = {vector['plaintext']}\n"
        f"  K = {vector['key']}\n"
        f"  C = {encrypted.hex().upper()}\n"
        f"  D(C) = {decrypted.hex().upper()}\n"
    )


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)

    summary = [
        "DES / AES-128 TEST VECTOR RESULTS",
        "",
    ]

    for vector in VECTORS:
        summary.append(run_vector(vector))

    report = "\n".join(summary)

    (RESULTS / "summary.txt").write_text(
        report + "\n", encoding="utf-8"
    )

    print("=" * 70)
    print(report)
    print(f"Results saved in: {RESULTS}")


if __name__ == "__main__":
    main()