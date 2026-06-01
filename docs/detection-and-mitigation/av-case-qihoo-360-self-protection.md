# Case study self-protection của Qihoo / 360

Cập nhật: 2026-06-02

## Phân loại

Nghiên cứu self-protection của Qihoo / 360 Total Security trong repo này được phân loại là:

```text
nghiên cứu phụ thuộc driver self-protection của AV
  -> driver sản phẩm thực thi bảo vệ runtime
  -> chính sách startup và service quyết định driver có hiện diện hay không
  -> nếu thiếu driver, lớp self-protection cấp cao có thể suy yếu
```

Trường hợp này khác với các case public prompt/IPC của Huorong và cũng khác với case trusted broker/quarantine consistency của Defender.

Tham chiếu sản phẩm chính:

- https://www.360totalsecurity.com/en/features/360-total-security/

Tham chiếu nghiên cứu lịch sử:

- The Antivirus Hacker's Handbook, O'Reilly:
  https://www.oreilly.com/library/view/the-antivirus-hackers/9781119028758/

## Hình dạng sản phẩm

360 Total Security là một security suite có real-time protection và nhiều engine/tính năng. Các thảo luận lịch sử về self-protection thường xoay quanh một driver sản phẩm chịu trách nhiệm bảo vệ process và component của sản phẩm khỏi hành vi local tamper.

Mô hình giản lược:

```text
service và UI sản phẩm
  -> driver self-protection
  -> bảo vệ process/file/registry/service
```

Driver là neo thực thi chính sách. Nếu driver hiện diện và hoạt động đúng, sản phẩm có thể chặn nhiều hành vi local tamper trực tiếp. Nếu driver vắng mặt lúc boot, các component user-mode của sản phẩm vẫn có thể tồn tại, nhưng neo self-protection đã mất.

## Case lịch sử về phụ thuộc driver startup

The Antivirus Hacker's Handbook thảo luận một case lịch sử về self-protection của Qihoo 360, trong đó việc làm yếu đường startup của driver self-protection khiến driver không load sau khi reboot.

Repo này không tái hiện registry path vận hành hoặc giá trị chính xác. Phân loại nghiên cứu sau là đủ:

```text
tamper chính sách startup
  -> driver self-protection không load
  -> kỳ vọng self-protection runtime không còn đúng
```

## Invariant bị phá vỡ

Invariant kỳ vọng:

```text
nếu sản phẩm đã cài và đang bật,
driver self-protection phải hiện diện trước khi attack surface user-mode của sản phẩm lộ ra
```

Áp lực lịch sử:

```text
cấu hình startup cục bộ có thể ngăn driver self-protection load
```

Invariant sâu hơn:

```text
self-protection không thể chỉ phụ thuộc vào một cờ startup có thể sửa được
```

Nếu sản phẩm tin rằng "driver đã load" là một sự thật runtime nhưng không bảo vệ đủ điều kiện khiến driver load, self-protection sẽ có khoảng hở ở thời điểm boot.

## Vì sao lớp lỗi này quan trọng

Driver self-protection runtime có thể rất mạnh sau khi đã load:

```text
driver đã load
  -> truy cập process/file/registry của sản phẩm được trung gian hóa
```

Nhưng cấu hình boot và service diễn ra trước hoặc quanh thời điểm driver bắt đầu hoạt động:

```text
cấu hình boot
  -> quyết định load driver
  -> bảo vệ runtime
```

Vì vậy, khả năng load của chính driver là một phần của security boundary.

Có thể diễn đạt câu hỏi cốt lõi như sau:

```text
ai bảo vệ lớp bảo vệ trước khi nó khởi động?
```

## Khác biệt với BYOVD

Case này tự thân không phải BYOVD.

BYOVD:

```text
attacker mang vào một driver đã ký nhưng có lỗ hổng
  -> lấy kernel primitive hoặc hành động đặc quyền
```

Phụ thuộc startup của self-protection 360:

```text
driver AV đã cài được kỳ vọng bảo vệ sản phẩm
  -> điều kiện startup/load bị sửa
  -> neo bảo vệ vắng mặt ở lần boot kế tiếp
```

Cả hai đều liên quan driver, nhưng hướng tin cậy ngược nhau:

- BYOVD lạm dụng một driver helper có lỗ hổng.
- Phụ thuộc startup của 360 làm yếu chính driver bảo vệ của sản phẩm.

## Khác biệt với Huorong

Các case công khai của Huorong:

```text
driver đang hoạt động
  -> tin nhầm vào UI/IPC/process coverage yếu
```

Case startup lịch sử của 360:

```text
driver không hoạt động
  -> sản phẩm mất neo bảo vệ
```

Huorong dạy bài học về độ tin cậy của decision channel. 360 dạy bài học về việc neo chính sách vào boot/load.

## Khác biệt với Defender

Self-protection tích hợp Windows của Defender dùng các khái niệm protected service cấp OS, Code Integrity, đăng ký ELAM, Tamper Protection và hành vi minifilter.

Case lịch sử của 360 nên được hiểu theo mô hình:

```text
driver riêng của sản phẩm phải load
  -> điều kiện load driver phải được bảo vệ
```

Case Medium của Defender là vấn đề trusted broker. Case 360 là vấn đề availability trước khi enforcement bắt đầu.

## Ma trận nghiên cứu

| Câu hỏi | Vì sao quan trọng |
|---|---|
| Driver 360 nào thực thi self-protection trên phiên bản này? | Security suite có thể đổi tên component và tách trách nhiệm theo phiên bản. |
| Driver là boot-start, system-start, demand-start hay do sản phẩm quản lý? | Thời điểm startup quyết định cửa sổ trước bảo vệ. |
| Cơ chế nào bảo vệ cấu hình service của driver? | Chính sách startup có thể sửa là điểm tamper giá trị cao. |
| Sản phẩm có phát hiện driver self-protection load thất bại không? | Thất bại phải tạo trạng thái unhealthy, không phải im lặng giảm bảo vệ. |
| Sản phẩm có sửa lại thiết lập startup của driver không? | Hành vi repair quyết định tamper có bền hay không. |
| Safe Mode hoặc sửa offline có làm đổi hành vi không? | Self-protection có thể vắng mặt ngoài normal boot. |
| Có nhiều driver có vai trò bảo vệ chồng lấn không? | Tắt một driver không nhất thiết làm tắt toàn bộ sản phẩm. |

## Ghi chú đọc lab an toàn

Khi đọc các writeup 360 cũ, tránh giả định phiên bản hiện tại có layout giống hệt. Thay vào đó, hãy ghi lại:

```text
phiên bản
danh mục driver
service start type
ai sở hữu service key
sản phẩm có tự sửa không
sản phẩm có báo health khi thiếu driver không
Windows Security Center còn xem sản phẩm là healthy không
```

Kết quả hữu ích không phải là "cách tắt 360". Kết quả hữu ích là mô hình:

```text
self-protection phụ thuộc vào neo ở thời điểm boot
```

## Failure mode thường gặp của self-protection phụ thuộc driver

- Product update đổi tên driver hoặc load order.
- Nhiều driver cùng thực thi chính sách chồng lấn.
- Watchdog service khôi phục thiết lập startup.
- Product cloud health đánh dấu thiếu self-protection.
- Windows policy hoặc Secure Boot làm đổi hành vi load driver.
- Driver start muộn hơn kỳ vọng, tạo một khoảng hở cục bộ ngắn.
- Driver load thất bại nhưng UI sản phẩm vẫn báo trạng thái healthy.

Điều kiện nghiên cứu thú vị nhất là mục cuối:

```text
driver vắng mặt
  + sản phẩm báo đã bảo vệ
  -> mâu thuẫn trạng thái health
```

## Câu hỏi ôn tập

1. Vì sao cấu hình driver startup là một phần của security boundary?
2. Sản phẩm nên làm gì nếu thiếu driver self-protection?
3. Vì sao "process sản phẩm đang chạy" yếu hơn "driver enforcement của sản phẩm đã load và healthy"?
4. Khác biệt giữa việc làm yếu driver bảo vệ của chính sản phẩm và việc lạm dụng driver bên thứ ba có lỗ hổng là gì?
5. Health reporting nên biểu diễn việc thiếu neo self-protection như thế nào?
6. Sau reboot nên kiểm tra trạng thái nào: service state, driver object, device object, UI sản phẩm, Windows Security Center hay backend health?

## Tham chiếu

- Trang tính năng chính thức của 360 Total Security:
  https://www.360totalsecurity.com/en/features/360-total-security/
- The Antivirus Hacker's Handbook, O'Reilly:
  https://www.oreilly.com/library/view/the-antivirus-hackers/9781119028758/
- Ghi chú repo về driver-load và Code Integrity:
  `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`
- Index AV self-protection:
  `docs/detection-and-mitigation/av-self-protection-research-index.md`
