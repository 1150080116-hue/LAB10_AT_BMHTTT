#  LAB 10: REMOTE DNS CACHE POISONING TRONG MÔI TRƯỜNG pfSense CÔ LẬP
## Link Youtube bài Lab: https://youtu.be/BxyDqkqejrA
- **Họ và tên:** Hoàng Minh Thắng
- **Mã số sinh viên (MSSV):** `1150080116`
---
## Mục tiêu Bài Lab

- **Phân biệt ranh giới tấn công:** Làm rõ sự khác biệt bản chất giữa **Local DNS Spoofing** (kẻ tấn công nằm chung broadcast domain và bắt trộm gói tin) với **Remote DNS Cache Poisoning / Kaminsky Attack** (kẻ tấn công từ xa, mù hoàn toàn thông tin gói tin).
- **Cách ly mạng tuyệt đối:** Sử dụng tường lửa pfSense để tách máy tấn công Kali sang một phân vùng riêng biệt (`ATTACKNET`), vô hiệu hóa khả năng nghe lén (`Promiscuous Mode = Deny`), chứng minh tính chất **Off-path / Blind Attacker**.
- **Khai thác lỗ hổng thiết kế DNS cổ điển:**
  - Vượt qua cơ chế phòng ngự của bộ nhớ đệm (DNS Cache TTL) bằng kỹ thuật truy vấn subdomain ngẫu nhiên.
  - Chạy đua đoán **Transaction ID 16-bit** trong cửa sổ trễ (Race Window).
  - Chiếm quyền điều khiển toàn bộ zone thông qua việc đầu độc bản ghi Name Server (`NS`) trong **Authority Section** và địa chỉ IP trong **Additional Section (Glue A)**.
- **Khôi phục & Kiểm chứng Hardening:** Khôi phục dịch vụ BIND9 hiện đại, quan sát cơ chế ngẫu nhiên hóa cổng nguồn UDP (**Source-Port Randomization - SPR** với entropy $2^{32}$ trạng thái), xác thực chữ ký số **DNSSEC**, và thiết lập **Recursion ACLs**.

---

## Kiến trúc Mạng & Phân vùng pfSense

Hệ thống được thiết lập trên nền tảng ảo hóa VirtualBox, kết nối qua 4 network interfaces của pfSense:

```
                                  ┌────────────────────────┐
                                  │      HOST MGMT         │
                                  │    192.168.56.1/24     │
                                  └───────────┬────────────┘
                                              │ (em0 / Management)
                         ┌────────────────────┴────────────────────┐
                         │             pfSense Firewall            │
                         └──────┬─────────────┬─────────────┬──────┘
                                │             │             │
                (em4 / 10.9.0.1)│             │             │(em5 / 10.10.0.1)
                                │             │             │
                    ┌───────────┴────────┐    │    ┌────────┴───────────┐
                    │    Vùng DNSLAB     │    │    │   Vùng ATTACKNET   │
                    │   10.9.0.0/24      │    │    │    10.10.0.0/24    │
                    ├────────────────────┤    │    ├────────────────────┤
                    │ DNS-SERVER:        │    │    │ KALI ATTACKER:     │
                    │   10.9.0.10        │    │    │   10.10.0.200      │
                    │ VICTIM:            │    │    │ (Promiscuous=Deny) │
                    │   10.9.0.100       │    │    └────────────────────┘
                    └────────────────────┘    │
                                              │(em3 / 172.16.6.1)
                                    ┌─────────┴──────────┐
                                    │      Vùng DMZ      │
                                    │    172.16.6.0/24   │
                                    ├────────────────────┤
                                    │ DMZ-WEB:           │
                                    │   172.16.6.10:80   │
                                    │ AUTH-DNS / RELAY:  │
                                    │   172.16.6.20:53   │
                                    └────────────────────┘
```

### Bảng Phân bổ Địa chỉ IP

| Thành phần | Vai trò kỹ thuật | Địa chỉ IP | Interface / Ghi chú |
| :--- | :--- | :--- | :--- |
| **pfSense DNSLAB** | Default Gateway cho DNS-LAB | `10.9.0.1/24` | `em4` (Internal Network: `dns-lab`) |
| **pfSense ATTACKNET** | Default Gateway cho Attacker | `10.10.0.1/24` | `em5` (Internal Network: `attack-net`) |
| **DNS-SERVER** | Recursive DNS Resolver | `10.9.0.10/24` | Upstream port mô phỏng: UDP 33333 |
| **VICTIM** | Client máy nạn nhân | `10.9.0.100/24` | Nameserver trỏ về `10.9.0.10` |
| **ATTACKER (Kali)** | Máy tấn công từ xa | `10.10.0.200/24` | Promiscuous Mode = Deny (Off-path) |
| **DMZ-WEB** | Máy chủ Web HTTP hợp lệ | `172.16.6.10/24` | Phục vụ trang web gốc `example.lab10.test` |
| **AUTH-DNS / RELAY** | Authoritative DNS & Race Relay | `172.16.6.20/24` | Port 53 (DNS) và Port 5300 (Race Relay) |

---

## Chính sách Tường lửa pfSense (Firewall Policy Ruleset)

Tường lửa pfSense kiểm soát nghiêm ngặt lưu lượng giữa các phân vùng, vừa cho phép kịch bản tấn công diễn ra, vừa ngăn chặn rò rỉ gói tin ra ngoài:

| Interface | Hành động | Nguồn (Source) | Đích (Destination) & Port | Mục đích kiểm soát |
| :---: | :---: | :--- | :--- | :--- |
| **DNSLAB** | Pass | `10.9.0.100` | `10.9.0.10` : UDP 53 | Nạn nhân gửi truy vấn DNS đệ quy tới Resolver |
| **DNSLAB** | Pass | `10.9.0.10` | `172.16.6.20` : UDP 53 | Resolver gửi truy vấn đệ quy lên Authoritative DNS hợp lệ |
| **DNSLAB** | Pass | `10.9.0.10` | `10.10.0.200` : UDP 53 | Resolver truy vấn Name Server độc hại sau khi bị đầu độc |
| **DNSLAB** | Pass | `10.9.0.100` | `10.10.0.200` : TCP 80 | Nạn nhân truy cập máy chủ Web giả mạo của Attacker |
| **DNSLAB** | Block & Log | `10.9.0.0/24` | Any khác (`10.6.0.0/24`, `192.168.56.0/24`) | Cô lập hoàn toàn vùng DNSLAB |
| **ATTACKNET** | Pass | `10.10.0.200` | `10.9.0.10` : UDP 53 | Attacker gửi truy vấn mồi để kích hoạt chu trình đệ quy |
| **ATTACKNET** | Pass | `10.10.0.200` | `172.16.6.20` : UDP 5300 | Attacker gửi batch dự đoán TXID vào race relay |
| **ATTACKNET** | Block & Log | `10.10.0.0/24` | Any khác (WAN, LAN, MGMT) | Chặn đứng Attacker không được ra Internet hay chạm các vùng khác |

---

## Cơ chế Tấn công Kaminsky DNS Poisoning

Cuộc tấn công của Dan Kaminsky (2008) giải quyết triệt để 2 rào cản lớn nhất của DNS Cache Poisoning cổ điển:

```
[Attacker 10.10.0.200]
     │
     │ 1. Trigger Query: "r87jhqx906v.example.lab10.test" (A?)
     ▼
[Resolver 10.9.0.10] ────( Cache Miss! )────► [AUTH-DNS 172.16.6.20]
     │                                            │ (Độ trễ xử lý / Race Window)
     │ 2. Query từ Source Port 33333, TXID=???    │
     │                                            │
     │◄── 3. Forged DNS Response mạo danh ────────┘
     │      (Khớp TXID & Port 33333)
     │      - Answer: NXDOMAIN
     │      - Authority: example.lab10.test. NS ns.evil.example.lab10.test.
     │      - Additional: ns.evil.example.lab10.test. A 10.10.0.200
     ▼
[Resolver Cache] ──► BỊ ĐẦU ĐỘC TOÀN BỘ ZONE!
     ▲
     │ 4. Client Query: "www.example.lab10.test" (A?)
     │
[Victim 10.9.0.100] ──► Nhận IP độc hại 10.10.0.200 ──► Mở FAKE SITE!
```

1. **Vượt qua Cache Effect:** Bằng cách tạo ra tiền tố subdomain ngẫu nhiên ở mỗi vòng lặp (`<random>.example.lab10.test`), Resolver không bao giờ có sẵn bản ghi trong Cache, bắt buộc phải phát sinh truy vấn mới ra bên ngoài tại mỗi vòng.
2. **Ủy quyền toàn bộ Zone (Authority Delegation):** Thay vì chỉ đầu độc một tên miền con ngẫu nhiên vô nghĩa, gói tin giả mạo gài bản ghi `NS` ủy quyền quyền quản trị toàn bộ zone `example.lab10.test` cho `ns.evil.example.lab10.test` và cung cấp địa chỉ IP thông qua bản ghi `Glue A` (`10.10.0.200`).
3. **Toán học Xác suất đoán TXID:**
   - Không gian Transaction ID 16-bit: $N = 2^{16} = 65,536$.
   - Mỗi batch Attacker gửi thử nghiệm $K = 4096$ giá trị TXID.
   - Xác suất trúng của mỗi batch: $P = \frac{4096}{65536} = \frac{1}{16} = 6.25\%$.
   - Sau tối đa 16 batch ($16 \times 4096 = 65,536$), không gian được vét cạn 100%.

---

##  Quy trình Thực nghiệm Từng Bước

### Giai đoạn 1: Xác nhận Baseline (Trước tấn công)
- Trên máy chủ `DNS-SERVER (10.9.0.10)`, chạy dịch vụ BIND9 với forward zone `example.lab10.test` trỏ về `172.16.6.20`.
- Trên máy `VICTIM (10.9.0.100)`, thực hiện truy vấn:
  ```bash
  dig @10.9.0.10 www.example.lab10.test
  ```
- **Kết quả:** Trạng thái `NOERROR`, `ANSWER SECTION` trả về đúng IP của máy chủ web hợp lệ: `172.16.6.10`.

### Giai đoạn 2: Chứng minh tính chất Remote (Không nghe lén)
- Trên máy `ATTACKER (10.10.0.200)`, chạy lệnh bắt gói tin:
  ```bash
  sudo tcpdump -i enp0s3 -n "host 172.16.6.20"
  ```
- Trong khi tcpdump đang chạy, từ `VICTIM` liên tục gửi truy vấn tới `DNS-SERVER`.
- **Kết quả:** `tcpdump` trên Attacker hiển thị **`0 packets captured`**. Attacker hoàn toàn bị cô lập khỏi luồng giao tiếp giữa Resolver và Upstream Server.

### Giai đoạn 3: Triển khai Tấn công Remote Kaminsky
- **Trên DNS-SERVER:** Tạm dừng BIND9 và khởi chạy resolver mô phỏng có nguồn phát cố định:
  ```bash
  sudo systemctl stop bind9
  sudo python3 vuln_resolver_lab10.py
  ```
- **Trên ATTACKER:** Khởi động dịch vụ DNS độc hại, web server giả mạo và script tấn công:
  ```bash
  sudo python3 evil_dns_lab10.py &
  python3 -m http.server 80 &
  python3 kaminsky_remote_lab10.py
  ```
- **Nhật ký Resolver ghi nhận:**
  ```text
  [CACHE] delegation poisoned: example.lab10.test. NS ns.evil.example.lab10.test. -> 10.10.0.200
  ```

### Giai đoạn 4: Kiểm chứng Hậu quả trên Nạn nhân (VICTIM)
- Trên máy `VICTIM`, thực hiện truy vấn lại tên miền:
  ```bash
  dig @10.9.0.10 www.example.lab10.test
  ```
   **Kết quả:** ANSWER SECTION trả về địa chỉ IP của kẻ tấn công: **`10.10.0.200`**!
- Cấu hình nameserver hệ thống và kiểm tra truy cập HTTP:
  ```bash
  echo "nameserver 10.9.0.10" | sudo tee /etc/resolv.conf
  curl http://www.example.lab10.test
  ```
   **Kết quả:** Trả về mã HTML của trang web giả mạo:
  ```html
  <h1>FAKE SITE 10.10.0.200</h1>
  ```

### Giai đoạn 5: Khôi phục BIND9 & Kiểm chứng Hardening
- Trên `DNS-SERVER`, tắt resolver mô phỏng và khởi động lại BIND9:
  ```bash
  sudo systemctl start bind9
  sudo tcpdump -i enp0s3 -n "udp and port 53"
  ```
- Từ `VICTIM`, gửi nhiều truy vấn DNS ngẫu nhiên.
- **Kết quả quan sát:**
  - BIND9 ngẫu nhiên hóa hoàn toàn UDP Source Port (các cổng quan sát được: `58822`, `36220`,...).
  - Resolver trả về `SERVFAIL`, từ chối các gói tin mạo danh, bảo vệ an toàn tuyệt đối cho bộ nhớ đệm.

---


##  Phân tích Giải pháp Phòng thủ (Hardening Strategies)

Để phòng chống triệt để tấn công Remote DNS Cache Poisoning trong môi trường sản xuất (Production), cần áp dụng mô hình **Phòng thủ theo chiều sâu (Defense-in-Depth)** gồm 4 tầng:

1. **Source-Port Randomization (SPR - RFC 5452):**
   - Thay vì dùng cổng nguồn cố định, Resolver bốc ngẫu nhiên một cổng UDP trong dải ephemeral ports (~60,000 cổng).
   - Gói tin phản hồi giả mạo phải khớp đồng thời cả **16-bit TXID** và **16-bit Port**, nâng tổng không gian tìm kiếm lên **$2^{32} \approx 4.3 \text{ tỷ khả năng}$**. Attacker không thể gửi đủ số gói tin trong cửa sổ vài mili-giây mà không bị nghẽn mạng hoặc kích hoạt hệ thống phát hiện xâm nhập.
2. **DNSSEC Validation (RFC 4033 / 4034 / 4035):**
   - Xác thực nguồn gốc dữ liệu và tính toàn vẹn bằng chữ ký số mật mã học (`RRSIG`) và chuỗi tin cậy (`Chain of Trust`).
   - Dù kẻ tấn công có đoán trúng cả TXID và Port, gói tin giả mạo vẫn bị Resolver hủy bỏ lập tức vì không sở hữu khóa bí mật để tạo chữ ký số hợp lệ.
3. **Quy tắc Thẩm quyền Bailiwick (RFC 2181):**
   - Resolver kiểm tra nghiêm ngặt phạm vi ủy quyền: Chỉ chấp nhận các bản ghi `NS` và `Glue A` nằm bên trong không gian tên miền của zone đang được truy vấn (*In-bailiwick*), từ chối lưu vào cache các bản ghi vượt quyền (*Out-of-bailiwick*).
4. **Hạn chế Quyền Đệ quy (Recursion Access Control):**
   - Cấu hình chỉ thị `allow-recursion { trusted_subnets; };` trên BIND9/Unbound để chỉ phục vụ các client nội bộ tin cậy, triệt tiêu nguy cơ máy chủ bị lợi dụng làm *Open Resolver*.
5. **Kỹ thuật 0x20 Encoding (RFC draft-vixie-dnsext-dns0x20):**
   - Ngẫu nhiên hóa cách viết hoa/thường trong chuỗi tên miền truy vấn (ví dụ: `wWw.ExAmPLe.CoM`). Phản hồi từ Authoritative Server bắt buộc phải bảo toàn chính xác cách viết này thì Resolver mới chấp nhận, bổ sung thêm hàng chục bit entropy chống giả mạo.







## Tuyên bố Miễn trừ Trách nhiệm (Disclaimer)

- Toàn bộ các kịch bản tấn công, mã nguồn mô phỏng và phân tích giao thức trong tài liệu này được thực hiện trong **môi trường phòng thí nghiệm mạng cô lập nội bộ (Isolated VirtualBox Testbed)** với tên miền thử nghiệm `.test` (theo tiêu chuẩn bảo vệ an toàn **RFC 2606** và **RFC 6761**).
- Dự án được thực hiện nhằm phục vụ mục đích **nghiên cứu học thuật, giáo dục và phát triển giải pháp phòng vệ an ninh hệ thống thông tin**.
- Nghiêm cấm mọi hành vi sao chép, sử dụng các công cụ và kỹ thuật này để tấn công hoặc xâm phạm bất hợp pháp vào hệ thống mạng của các cơ quan, tổ chức hoặc cá nhân trên Internet.

---


