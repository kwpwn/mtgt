# DHCP / ipconfig release & renew — Khái niệm chi tiết

---

## 1. DHCP là gì?

**DHCP (Dynamic Host Configuration Protocol)** là giao thức tự động cấp phát cấu hình mạng
cho máy tính, bao gồm:

- IP address (ví dụ: 192.168.1.100)
- Subnet mask (ví dụ: 255.255.255.0)
- Default gateway (ví dụ: 192.168.1.1)
- DNS server (ví dụ: 8.8.8.8)

Khi máy khởi động và cắm mạng, nó thực hiện quá trình **DORA**:

```
Client                          DHCP Server
  |                                  |
  |──── DISCOVER (broadcast) ───────►|   "Có ai cấp IP cho tôi không?"
  |◄─── OFFER ──────────────────────|   "Tôi offer IP 192.168.1.100"
  |──── REQUEST (broadcast) ────────►|   "Tôi chọn offer của anh"
  |◄─── ACK ────────────────────────|   "OK, IP là của anh, lease 24h"
```

Sau ACK, máy có IP + gateway + DNS → ra mạng được.
IP này có **lease time** (thời hạn thuê), thường 24h–7 ngày tùy router.

---

## 2. ipconfig /release — DHCP Release

```
C:\> ipconfig /release
```

**Làm gì:**
- Gửi gói **DHCP RELEASE** đến DHCP server: "Tôi trả lại IP này"
- Windows xóa IP, subnet mask, default gateway khỏi adapter
- Adapter vẫn **ENABLED** ở OS level (NIC driver vẫn chạy)
- Adapter không có IP → tự gán APIPA (169.254.x.x) hoặc để trống

**Hậu quả ngay lập tức:**
- Không ping được bất cứ đâu (không có IP → không route packet được)
- Mọi TCP connection đang mở bị **drop ngay**
- Beacon mất kết nối về C2

**Lưu ý quan trọng:** Hardware/driver vẫn UP, chỉ là không có IP.

---

## 3. ipconfig /renew — DHCP Renew

```
C:\> ipconfig /renew
```

**Làm gì:**
- Thực hiện lại REQUEST → ACK với DHCP server
- Lấy lại IP (có thể IP cũ hoặc IP mới)
- Adapter hoạt động bình thường trở lại

Thường dùng sau `/release` để lấy lại IP mới.

---

## 4. Tác dụng thực tế với bài toán CTF

### Kịch bản 1 NIC (phổ biến nhất):

```
Victim:
  Ethernet0 ── DHCP IP ── gateway ── Internet + C2 VPS
                 └── Beacon đi qua đây
                 └── Victim browse internet qua đây
```

**Nếu release Ethernet0:**
```
SAU release:
  Ethernet0 không có IP
  Beacon → FAIL ✗   (cũng mất IP)
  Victim  → FAIL ✗
```

→ **Không dùng được** — cắt hết cả beacon lẫn internet.

---

### Kịch bản 2 NIC:

```
Victim:
  Ethernet0 ── C2 adapter  (giữ lại)
  Ethernet1 ── Internet NIC (release/disable cái này)
```

**Nếu release + disable Ethernet1:**
- Victim mất IP trên Ethernet1 → không dùng Ethernet1 ra internet được
- Beacon vẫn sống qua Ethernet0

**Vẫn còn vấn đề trong lab:** Nếu cả 2 NIC đều là NAT (như lab hiện tại),
victim vẫn ra internet được qua Ethernet0 (C2 adapter).

---

## 5. So sánh các phương pháp cắt mạng

| Phương pháp            | Victim mất mạng | Beacon sống | Ghi chú |
|------------------------|:-:|:-:|---------|
| `ipconfig /release`    | ✓ | ✗ | Beacon cũng mất IP |
| Disable NIC (1 NIC)    | ✓ | ✗ | Kill cả beacon |
| Release + Disable NIC  | ✓ | ✗ | Chắc hơn nhưng vẫn kill beacon |
| **Route isolation**    | **✓** | **✓** | Xóa default GW, giữ route C2/32 |
| Firewall rules         | ✓ | ✓ | Block all outbound, allow C2 IP |

---

## 6. Tại sao Route Isolation là đúng?

```
TRƯỚC nic-isolate:
  Route table:
    0.0.0.0/0  → 192.168.1.1  (default gateway — tất cả đi qua đây)

  Beacon  → C2_IP → 192.168.1.1 → Internet ✓
  Victim  → Google → 192.168.1.1 → Internet ✓

SAU nic-isolate:
  Route table:
    C2_IP/32  → 192.168.1.1  (chỉ route này còn lại)
    0.0.0.0/0 → XÓA

  Beacon  → C2_IP → 192.168.1.1 ✓  (có route /32 cụ thể)
  Victim  → Google → NO ROUTE ✗     (không có default gateway)
  Victim  → ping 8.8.8.8 → NO ROUTE ✗
```

NIC vẫn UP, IP vẫn còn, driver vẫn chạy.
Chỉ là Windows không biết forward packet đi đâu ngoài C2 IP.

---

## 7. Kết luận

| Câu hỏi | Trả lời |
|---------|---------|
| DHCP release có cắt mạng victim không? | Có |
| Beacon có sống sau release không? | Không (nếu dùng chung NIC) |
| Khi nào release hữu ích? | Khi có 2 NIC tách biệt, release NIC không phải C2 |
| Cách tốt nhất cho 1 NIC? | Route isolation hoặc Firewall rules |

**Trong BOF hiện tại:**
- `nic-off` = DHCP release + Disable NIC → cắt mạng hoàn toàn (beacon chết nếu chung NIC)
- `nic-isolate` = Xóa default gateway → victim mất internet, beacon sống
