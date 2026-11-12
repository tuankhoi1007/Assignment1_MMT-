<p align="center">
  <img src="logo.png" width="120" alt="Trường ĐH Bách Khoa - ĐHQG TP.HCM Logo" />
</p>

# Assignment 1: Distributed Streaming Collaboration System
> **Môn học:** CO3093 / CO3094 – Mạng Máy Tính & Phát triển Ứng dụng Mạng (HCMUT)  
> **Dự án:** Ứng dụng cộng tác Client-Server và Peer-to-Peer thời gian thực dựa trên kết nối phân tán và streaming.

---

## 1. Giới thiệu

Hệ thống được xây dựng **100% bằng Socket thuần mức thấp** (`import socket`), hoàn toàn không sử dụng web framework bậc cao (Flask, Django, Tornado) hay WebSockets:
- **TCP Signaling Plane (Port 8888):** Bắt tay 2 chiều kèm trao đổi khóa X25519, đăng nhập bằng mật khẩu (scrypt), danh bạ online và nhắn tin end-to-end (Broadcast & Unicast).
- **UDP Data Streaming Plane (Port 8889 / Dynamic):** Truyền file tin cậy bằng **Selective Repeat** + **CUBIC** (RTO thích nghi theo RFC 6298), chunk 1200B dưới MTU, đối soát SHA-256. Cổng 8889 của server vừa nhận heartbeat vừa relay file khi hai peer không gặp nhau trực tiếp.
- **Bảo mật Tầng Ứng dụng:** AES-256-GCM với khóa riêng từng cặp peer (X25519 + HKDF). Server chỉ chuyển ciphertext.
- **Web UI Socket thuần (Zero-Framework):** Tự xây dựng HTTP/1.1 server bằng socket phục vụ giao diện Web Dashboard, quản lý phiên Cookie RFC 6265, Basic Auth RFC 7235 và hiển thị thông báo tin nhắn chưa đọc.

---

## 2. Cài đặt

- **Yêu cầu môi trường:** Python 3.10 trở lên (Windows / macOS / Linux).
- **Cài đặt thư viện mật mã:**
  ```bash
  pip install cryptography
  ```

---

## 3. Hướng dẫn Chạy Hệ Thống

### Cách 1: Chạy trên cùng 1 máy tính (Localhost)

Server mặc định **bắt buộc mật khẩu**. Tài khoản được ghi vào `server/users.json` (hash scrypt + salt, không lưu mật khẩu thô). Lần đầu dùng `--register`.

Mở 3 cửa sổ Terminal riêng biệt:

1. **Terminal 1 – Khởi động Server trung tâm:**
   ```bash
   python -m server.run_server
   ```
   *(TCP `0.0.0.0:8888`, UDP `8889` cho heartbeat và relay file).*

2. **Terminal 2 – Đăng ký và đăng nhập Alice:**
   ```bash
   python -m client.run_client Alice --password alice123 --register
   ```
   *(Lần sau bỏ `--register`. Web Dashboard mở tại `http://127.0.0.1:5001`.)*

3. **Terminal 3 – Đăng ký và đăng nhập Bob:**
   ```bash
   python -m client.run_client Bob --password bob123 --register
   ```
   *(Web Dashboard tại `http://127.0.0.1:5002`.)*

Có thể đăng ký ngay trên Web UI: nhập username, password, tick **Create new account**, rồi Connect.

Muốn chạy kiểu cũ (chỉ cần tên, không mật khẩu) thì khởi động server với `--allow-guest`:

```bash
python -m server.run_server --allow-guest
python -m client.run_client Alice
```

Tên đã đăng ký vẫn phải đúng mật khẩu, kể cả khi bật guest.

---

### Cách 2: Chạy trên 2 máy tính khác nhau (Cùng mạng LAN / Wi-Fi)

1. **Trên Máy 1 (Server & Alice):**
   - Mở Terminal gõ `ipconfig` (hoặc `ifconfig` trên Linux/macOS) để lấy địa chỉ IPv4 (ví dụ: `192.168.1.15`).
   - Khởi động Server:
     ```bash
     python -m server.run_server
     ```
   - Khởi động Client Alice:
     ```bash
     python -m client.run_client Alice --password alice123 --register
     ```

2. **Trên Máy 2 (Client Bob kết nối sang Máy 1):**
   - Chạy lệnh kết nối tới IP Máy 1:
     ```bash
     python -m client.run_client Bob --host 192.168.1.15 --password bob123 --register
     ```
   *(Trình duyệt trên Máy 2 sẽ tự động mở Web UI và kết nối trực tiếp đến Server tại `192.168.1.15:8888`).*

---

## 4. Hướng dẫn Sử dụng Giao diện Web UI

- **Chat công khai (Global Chat 🌐):** Chọn kênh *Global Chat* ở cột bên trái để gửi tin nhắn đến tất cả mọi người đang online.
- **Chat riêng tư (Direct Messages 💬):** Nhấp chọn một người dùng cụ thể (như Bob, Trudy) để gửi tin nhắn trực tiếp được mã hóa E2EE.
- **Hệ thống thông báo:** 
  - Tiêu đề tab trình duyệt tự động cập nhật tổng số tin nhắn chưa đọc: `(3) Assignment 1...`
  - Từng kênh/người gửi hiển thị huy hiệu đỏ chứa số lượng tin chưa đọc. Khi nhấp vào đọc, thông báo sẽ tự động biến mất.
- **Truyền file UDP Streaming (📁):** 
  - Tại bảng bên phải, chọn người nhận trong menu *Recipient Peer*.
  - Nhấp *Select File* để chọn tệp tin bất kỳ từ máy tính.
  - Bấm *Start UDP Streaming Transfer*: thanh tiến trình chạy từ $0\%$ đến $100\%$. Tick *Send through server relay* nếu muốn file đi qua UDP 8889 thay vì P2P.
  - Người nhận sẽ thấy nút **Open** để mở tệp ngay lập tức (tệp được lưu tại thư mục `client/downloads/`).
  - Huy hiệu cạnh tên hiển thị cổng UDP; đưa chuột lên đó để xem fingerprint khóa công khai (so sánh ngoài băng với peer).

---

## 5. Chạy Kiểm Thử Tự Động (Unit Tests)

Bộ test chạy trên localhost: framing TCP/UDP, AES-GCM, Selective Repeat (kể cả mất gói giả lập), 15 client đồng thời, REST API, và các cơ chế ở mục 7 (CUBIC, X25519, relay, FIN, mật khẩu, heartbeat UDP).

```bash
python -m unittest discover tests -v
```

Kết quả mong đợi: `Ran 46 tests ... OK`.

---

## 6. Cấu trúc Thư mục

```text
assignment1/
├── protocol/               # TCP 20B, UDP 24B, X25519 + AES-GCM, Selective Repeat + CUBIC
├── server/                 # Server đa luồng, scrypt, relay UDP 8889, watchdog
├── client/                 # Client engine, HTTP socket thuần và Web Dashboard
│   ├── downloads/          # Thư mục lưu tệp nhận qua UDP
│   └── web/                # Giao diện Web UI (index.html, style.css, app.js)
├── tests/                  # Unit test và integration test trên localhost
└── README.md               # Hướng dẫn cài đặt và vận hành
```

---

## 7. Các cơ chế bổ sung

### 7.1. Kiểm soát nghẽn CUBIC và RTO thích nghi

Cửa sổ gửi không còn cố định 8 chunk. `RttEstimator` tính SRTT và RTTVAR theo RFC 6298, rồi RTO = SRTT + max(G, 4·RTTVAR), kẹp trong khoảng 50 ms–3 s. Timeout thì RTO nhân đôi. Mẫu RTT chỉ lấy từ chunk gửi một lần (Karn).

`CongestionController` là CUBIC (RFC 8312), đơn vị là chunk:

- Slow start: +1 chunk mỗi ACK cho tới `ssthresh`.
- Congestion avoidance: W(t) = C·(t−K)³ + W_max, với C = 0.4 và K = ∛(W_max·(1−β)/C), β = 0.7. Mỗi ACK tiến về phía max(W_cubic, W_est). Khi cwnd đang nằm trên đường cong, nhánh TCP-friendly tăng 1/cwnd mỗi ACK.
- Mất gói (3 ACK của chunk đứng sau một lỗ hổng): ssthresh = cwnd·β, cwnd = ssthresh, và chỉ gửi lại chunk đó (fast retransmit). Nếu cwnd chưa đạt W_max cũ thì W_max mới = cwnd·(1+β)/2 (fast convergence). Trong fast recovery (base còn ≤ recovery point) ACK mới không làm cwnd tăng. Recovery kết thúc khi mọi chunk tới recovery point đã được ACK.
- Timeout: ssthresh = cwnd·β, cwnd = 1, quay lại slow start.

`WINDOW_SIZE` (64) chỉ là trần flow-control. Cửa sổ thực tế là min(cwnd, trần đó).

`--congestion bbr` chọn bộ điều khiển tùy chọn BBR-lite: cwnd bám bandwidth-delay product (gain 2 lúc startup, gain 1 sau đó). Một fast retransmit không nhân cửa sổ với β; timeout thì cửa sổ về giá trị ban đầu. Đây không phải BBR đầy đủ (không có chu kỳ pacing gain hay ProbeRTT).

### 7.2. Trao đổi khóa X25519 (mã hóa đầu-cuối)

Mỗi lần đăng nhập client tạo một cặp khóa X25519 mới.

- Handshake: client gửi khóa công khai, server trả khóa tạm của kết nối. Hai bên tính khóa kênh bằng HKDF-SHA256. Mật khẩu đi trong kênh này. Khóa HMAC cho heartbeat UDP là một khóa dẫn xuất khác (`udp-heartbeat`), không phải token gửi rõ.
- Chat unicast và từng file dùng khóa riêng của đúng cặp peer (`context` là `chat` hoặc `file:<stream_id>`). Broadcast là một ciphertext cho mỗi peer đang online, không phải một khóa chung.
- Chunk file gắn thêm AAD (stream id, chỉ số chunk, tổng số chunk) nên không đổi chỗ các chunk cho nhau được.
- Server không có khóa riêng của peer và không gọi giải mã trên chat hay file.

Khóa công khai do server phân phối và không được chứng thực. Server đổi khóa thì chen giữa được. Fingerprint (16 hex đầu của SHA-256, hiện khi rê chuột lên cổng UDP) dùng để đối chiếu ngoài băng.

### 7.3. Relay UDP cổng 8889

Server bind UDP 8889 và chạy vòng nhận. `FILE_ANNOUNCE` đăng ký route `stream_id → (sender, target)`. Gói DATA/FIN được chuyển nguyên vẹn từ sender sang target; ACK đi ngược lại. Payload vẫn là ciphertext của hai peer.

Đường mặc định là P2P tới IP và cổng UDP mà server thấy lúc login. Nếu sau 1 giây không có ACK nào, sender gửi lại toàn bộ phần chưa ACK qua relay (NAT hoặc firewall chặn P2P). Có thể buộc relay ngay từ đầu bằng `--force-relay` hoặc checkbox *Send through server relay* trên Web UI.

### 7.4. Gói FIN (Type = 3)

Khi mọi chunk đã được ACK, sender gửi FIN. Receiver trả ACK với cờ `FLAG_FIN` rồi xóa trạng thái nhận. Sender gửi lại FIN nếu ACK mất; mỗi lần chờ lâu gấp đôi (tối đa 3 giây), tối đa 5 lần. Hủy giữa chừng hoặc gửi thất bại thì cùng handshake đó với `FLAG_ABORT`. Receiver luôn ACK FIN hủy (kể cả lần gửi lại), đánh dấu hủy và xóa trạng thái, không ghép file. FIN thường bị bỏ qua nếu file còn thiếu chunk.

### 7.5. Đăng nhập bằng mật khẩu

`server/credentials.py` lưu scrypt (N=2¹⁴, r=8, p=1) với salt ngẫu nhiên 16 byte trong `server/users.json`. File này có thể copy sang máy khác để dùng lại tài khoản. Mật khẩu sai hoặc gửi dạng plaintext (không qua khóa kênh) nhận `AUTH_FAILURE`. `AUTH_REGISTER` tạo tài khoản rồi đăng nhập luôn. `--allow-guest` chỉ mở cửa cho tên chưa đăng ký.

### 7.6. Heartbeat và discovery trên UDP

Đúng theo mục Techniques của đề, client gửi heartbeat UDP (type 4) tới cổng 8889. Thân gói được HMAC-SHA256 bằng khóa suy ra từ handshake X25519 (`context` là `udp-heartbeat`), kèm bộ đếm tăng dần để chặn replay. Token đăng nhập không nằm trong gói UDP. Server kiểm tra MAC. Nếu gói đến từ đúng địa chỉ đã xác nhận thì chỉ cập nhật thời điểm sống. Nếu địa chỉ nguồn là mới, server gửi một challenge (ACK type 5) và chỉ ghi `udp_addr` khi client gửi lại challenge đó từ cùng địa chỉ, trong một heartbeat mới. Token rõ hoặc gói replay không đổi được địa chỉ relay.

Relay file chỉ chuyển DATA, ACK và FIN giữa hai đầu đã đăng ký cho `stream_id`. Địa chỉ nguồn phải trùng địa chỉ UDP đã xác thực của đúng người gửi hướng đó. Gói từ địa chỉ khác bị bỏ, và relay không tự học địa chỉ từ gói file.

Danh bạ (ai đang online, khóa công khai) vẫn đi trên TCP vì cần tin cậy. Nếu vài chu kỳ không thấy pong UDP, client gửi thêm `HEARTBEAT_PING` trên TCP để watchdog 15 giây không đá nhầm máy bị chặn UDP. Watchdog vẫn xóa session im lặng quá 15 giây và báo `USER_LEFT`.

Sau khi login, socket TCP của session không còn recv-timeout. Heartbeat đi trên UDP nên đường TCP có thể im; timeout recv sẽ cắt nhầm session còn sống. Socket chưa login vẫn bị đóng sau 60 giây nếu không gửi gì.
