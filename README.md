# Lý thuyết mật mã — DES và AES-128

## Thông tin sinh viên

- Họ và tên: Trần Đức Đạt
- MSSV: 20233311
- Ngôn ngữ lập trình: Python

## Mục tiêu bài tập

Cài đặt thuật toán DES và AES-128, kiểm tra bằng test vector
và in các trạng thái trung gian để đối chiếu từng bước.

## Nội dung triển khai

### DES

- Sinh 16 khóa vòng.
- Thực hiện hoán vị ban đầu.
- Thực hiện 16 vòng Feistel.
- Thực hiện hoán vị cuối để tạo bản mã.
- Giải mã bằng cách đảo thứ tự khóa vòng.
- In khóa và các giá trị trung gian của từng vòng.

### AES-128

- Biểu diễn khối dữ liệu bằng ma trận trạng thái 4×4 byte.
- Sinh các khóa vòng bằng Key Expansion.
- Thực hiện AddRoundKey ban đầu.
- Thực hiện 9 vòng đầy đủ.
- Thực hiện vòng cuối không có MixColumns.
- Giải mã bằng các phép biến đổi nghịch đảo.
- In trạng thái sau mỗi phép biến đổi.

## Kiểm tra kết quả

- So sánh bản mã với đầu ra kỳ vọng của test vector.
- Kiểm tra các giá trị trung gian.
- Kiểm tra giải mã khôi phục đúng bản rõ.
- Lưu kết quả chạy vào thư mục results.

## Phạm vi

Chương trình phục vụ học tập, xử lý từng khối dữ liệu:
DES có khối 64 bit, AES-128 có khối và khóa 128 bit.

Các test vector cần được đối chiếu với ví dụ giảng viên
đã thực hiện trên bảng trước khi nộp bài.

## Cấu trúc chương trình

- `des.py`: cài đặt DES, sinh khóa và ghi trạng thái từng vòng.
- `aes.py`: cài đặt AES-128 và các phép biến đổi nghịch đảo.
- `main.py`: chạy test vector, in và lưu kết quả.
- `test_algorithms.py`: kiểm tra đầu ra và trạng thái trung gian.
- `results/`: kết quả thực chạy để đối chiếu.
- `.gitignore`: loại bỏ tệp tạm khỏi Git.

## Cách chạy

Yêu cầu Python 3.10 trở lên. Không cần cài thêm thư viện.

Mở Terminal tại thư mục chứa `main.py` rồi chạy:

```bash
python main.py
python test_algorithms.py
```

Trên Windows, có thể dùng `py` thay cho `python`.

## Test vector

| Ví dụ | Bản rõ (hex) | Khóa (hex) | Bản mã kỳ vọng (hex) |
|---|---|---|---|
| DES | 0123456789ABCDEF | 133457799BBCDFF1 | 85E813540F0AB405 |
| AES trong tài liệu | 3243F6A8885A308D313198A2E0370734 | 2B7E151628AED2A6ABF7158809CF4F3C | 3925841D02DC09FBDC118597196A0B32 |
| AES FIPS 197 | 00112233445566778899AABBCCDDEEFF | 000102030405060708090A0B0C0D0E0F | 69C4E0D86A7B0430D8CDB78070B4C55A |

Nguồn của từng vector được ghi trong `main.py`.
Cần đối chiếu với các ví dụ thực tế trên bảng trước khi nộp.

## Đọc kết quả

- `results/summary.txt`: kết quả kiểm tra các test vector.
- `results/des_classic_encrypt.txt`: toàn bộ bước mã hóa DES.
- `results/des_classic_decrypt.txt`: toàn bộ bước giải mã DES.
- `results/aes_class_example_encrypt.txt`: mã hóa ví dụ AES trong tài liệu.
- `results/aes_class_example_decrypt.txt`: giải mã ví dụ AES trong tài liệu.
- `results/aes_fips197_encrypt.txt`: mã hóa vector AES FIPS 197.
- `results/aes_fips197_decrypt.txt`: giải mã vector AES FIPS 197.
- `results/test_run.txt`: báo cáo kiểm thử.

## Quy ước

- Đầu vào là hex, không phải chuỗi ký tự ASCII.
- State AES được điền và nối thành chuỗi theo cột.
- DES đổi hai nửa thành R16 || L16 trước hoán vị cuối.
- AES-128 có 10 vòng; vòng mã hóa cuối không có MixColumns.
- Chương trình không tự đệm dữ liệu và không triển khai CBC/CTR.
- Khóa DES gồm các bit parity; PC1 loại bỏ các bit này.

## Ghi chú học tập

Mã được xây dựng với hỗ trợ AI
