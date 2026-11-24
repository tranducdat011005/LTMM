#LTMM — Cài đặt DES và AES-128

Sinh viên: Trần Đức Đạt
MSSV: 20233311
Ngôn ngữ: Python 3.10 trở lên

Bài thực hành cài đặt trực tiếp DES và AES-128, in khóa vòng và trạng thái trung gian, kiểm tra kết quả bằng test vector. Phần thuật toán chỉ sử dụng thư viện chuẩn Python. Mã hóa và giải mã đều được triển khai.

1. Chạy bài

Chạy các lệnh sau từ thư mục chứa "main.py".

```bash
python main.py demo
python -m unittest discover -s tests -v
```

Chạy riêng ví dụ DES, hiển thị đầy đủ trạng thái:

```bash
python main.py des --key 133457799BBCDFF1 --block 0123456789ABCDEF
python main.py des --key 133457799BBCDFF1 --block 85E813540F0AB405 --decrypt
```

Chạy riêng AES-128:

```bash
python main.py aes --key 000102030405060708090A0B0C0D0E0F --block 00112233445566778899AABBCCDDEEFF
python main.py aes --key 000102030405060708090A0B0C0D0E0F --block 69C4E0D86A7B0430D8CDB78070B4C55A --decrypt
```

2. Test vector và kết quả

Mọi số trong bảng là "hex", không phải chuỗi ký tự ASCII.

| Ví dụ | Bản rõ | Khóa | Bản mã kỳ vọng |
|---|---|---|---|
| DES | "0123456789ABCDEF" | "133457799BBCDFF1" | "85E813540F0AB405" |
| AES trong tài liệu | "3243F6A8885A308D313198A2E0370734" | "2B7E151628AED2A6ABF7158809CF4F3C" | "3925841D02DC09FBDC118597196A0B32" |
| AES FIPS 197 C.1 | "00112233445566778899AABBCCDDEEFF" | "000102030405060708090A0B0C0D0E0F" | "69C4E0D86A7B0430D8CDB78070B4C55A" |

Các ví dụ được xác định từ tài liệu đã cung cấp và chuẩn AES.

Nguồn, tính theo số trang của tệp PDF, bao gồm trang bìa:

- DES: `tong-hop-tai-lieu-cuoi-ky-math-101-gcd-modular-arithmetic-cryptography.pdf`, trang 10–17.
- AES ví dụ đầu: `tom-tat-ly-thuyet-mat-ma-ma-co-dien-va-hien-dai.pdf`, trang 20–25; cũng là ví dụ Appendix B của FIPS 197 bản 2001.
- AES ví dụ thứ hai: FIPS 197 bản 2001, Appendix C.1; tài liệu tóm tắt trên dùng bản mã của ví dụ này ở trang 26 để minh họa giải mã.
- Bảng DES theo [FIPS 46-3](https://csrc.nist.gov/pubs/fips/46-3/final); AES theo [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final). Bản cập nhật AES năm 2023 giữ nguyên thuật toán, bố cục phụ lục khác bản 2001.

3. Các tệp cần xem

| Tệp | Nội dung |
|---|---|
| `src/des.py` | Bảng hoán vị, S-box, sinh 16 khóa, Feistel, mã hóa/giải mã DES |
| `src/aes.py` | GF(2⁸), S-box, bốn phép biến đổi, 44 word khóa, mã hóa/giải mã AES-128 |
| `main.py` | Giao diện dòng lệnh, in trace và chạy các vector |
| `vectors.json` | Đầu vào, đầu ra kỳ vọng và nguồn của các ví dụ |
| `tests/test_algorithms.py` | Kiểm thử đầu ra và các giá trị trung gian cố định |
| `verify_reference.py` | Đối chiếu tùy chọn với thư viện độc lập |
| `results/*_encrypt.txt` | Khóa vòng và toàn bộ trạng thái mã hóa |
| `results/*_decrypt.txt` | Khóa vòng và toàn bộ trạng thái giải mã |
| `results/*.json` | Cùng các trạng thái ở dạng dữ liệu có cấu trúc |
| `docs/LOI_GIAI.md` | Công thức, giải tay vòng đầu, bảng kết quả các vòng |
| `.github/workflows/tests.yml` | Chạy kiểm thử và kiểm tra tái tạo trace khi push/PR |

## 4. Nội dung kiểm định

DES in `PC1`, `C0`, `D0`, các lần dịch vòng, `K1…K16`, `IP`, `L0`, `R0`; với từng vòng in `E(R)`, XOR khóa, từng nhóm 6 bit qua S-box cùng hàng/cột, đầu ra S-box, hoán vị P, `Li`, `Ri`; cuối cùng in `R16 || L16` và đầu ra `IP⁻¹`.

AES in `w[0]…w[43]`, RotWord/SubWord/Rcon và phép XOR trong sinh khóa, `K0…K10`; in state sau từng SubBytes, ShiftRows, MixColumns, AddRoundKey. Mỗi state có chuỗi hex nối theo cột và ma trận 4×4 in theo hàng. Giải mã cũng in các bước nghịch đảo. Trace có 41 state cho mỗi chiều, tính cả đầu vào.

12 bài kiểm thử kiểm tra vector chuẩn hai chiều, vector toàn 0, giá trị trung gian vòng đầu, khóa vòng cuối, cách xử lý parity DES, thứ tự khóa giải mã, phép nghịch đảo, phép nhân GF và đầu vào sai. Đầu ra kỳ vọng là hằng số độc lập, không chỉ kiểm tra `D(E(P)) = P`.

Đối chiếu bổ sung, **tùy chọn**:

```bash
python -m pip install cryptography
python verify_reference.py
```

Đã đối chiếu 100 cặp khóa/khối cho mỗi thuật toán, cả mã hóa và giải mã: **400 phép so sánh khớp**. Seed kiểm thử cố định là `3310`. Với DES, oracle dùng TripleDES với ba khóa bằng nhau, tương đương DES. Thư viện này chỉ được dùng trong tệp kiểm chứng, không tham gia triển khai thuật toán. Báo cáo môi trường và kết quả thực chạy nằm ở `results/test_run.txt` và `results/reference_check.txt`.

## 5. Phạm vi và việc cần hoàn thiện trước khi nộp

Bài xử lý **một khối**: DES 8 byte, AES 16 byte; không tự padding, không có IV hay chế độ CBC/CTR. Khóa DES nhập 8 byte gồm parity, PC1 loại các bit parity; chương trình không ép sửa hay từ chối parity sai. AES chỉ nhận khóa 128 bit.

Đây là mã học thuật có in cả khóa và trạng thái; không dùng để bảo vệ dữ liệu thật. DES đã lỗi thời. Đầu vào CLI là hex: 32 ký tự hex biểu diễn 16 byte, khác với 32 ký tự ASCII. Họ tên có dấu dùng để ghi thông tin sinh viên, không tự biến thành bản rõ 16 byte.

Bổ sung MSSV/lớp nếu môn học yêu cầu, xác nhận ví dụ trên bảng và nộp link repository riêng. Đề nhấn mạnh “không vibe code”: cần tự đọc, chạy, giải thích được từng hàm và các phép tính trong lời giải; tuân theo quy định của lớp về hỗ trợ AI. Bộ tệp này được chuẩn bị với hỗ trợ AI và đã kiểm thử, không phải bằng chứng người nộp tự viết toàn bộ mã.
