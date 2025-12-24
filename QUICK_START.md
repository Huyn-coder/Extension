# 🚀 PhishShield - Hướng dẫn khởi động nhanh

## Bước 1: Cài đặt dependencies cho Backend

```bash
cd backend
pip install -r requirements.txt
```

## Bước 2: Khởi động Backend Server

```bash
cd backend
python -m uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

Server sẽ chạy tại: http://localhost:8000

### Kiểm tra API:
- Mở browser và truy cập: http://localhost:8000
- Bạn sẽ thấy: `{"message": "PhishShield API is running 🚀"}`

## Bước 3: Cài đặt Extension vào Chrome

1. Mở Chrome browser
2. Truy cập `chrome://extensions/`
3. Bật **Developer mode** (toggle ở góc trên bên phải)
4. Click nút **Load unpacked**
5. Chọn thư mục: `Developing_Phishing_Detection_Solution-main/Extension`
6. Extension PhishShield sẽ xuất hiện với icon 🛡️

## Bước 4: Sử dụng Extension

1. Mở bất kỳ trang web nào
2. Click vào icon PhishShield trên thanh công cụ Chrome
3. Xem kết quả phân tích URL với mức độ nguy hiểm

## 🎯 Các tính năng chính

| Tính năng | Mô tả |
|-----------|-------|
| Auto-scan | Tự động quét URL khi bạn duyệt web |
| Risk Badge | Hiển thị mức độ nguy hiểm trên icon |
| Link Scanner | Quét tất cả links trên trang |
| Report | Báo cáo URL đáng ngờ |
| Whitelist | Đánh dấu trang tin cậy |
| Blacklist | Chặn trang nguy hiểm |

## 🔧 Cấu hình (Tùy chọn)

### Đổi API URL
Chỉnh file `Extension/config.js`:
```javascript
API_URL: "http://your-server:8000"
```

### Cấu hình MongoDB (cho whitelist/blacklist)
Tạo file `.env` trong thư mục `backend`:
```
MONGO_URI=mongodb://localhost:27017/phishshield
```

## ❓ Troubleshooting

### Extension không hiển thị kết quả
- Kiểm tra backend server đang chạy: http://localhost:8000
- Mở Chrome DevTools (F12) và check Console cho lỗi

### Badge không cập nhật
- Reload extension tại `chrome://extensions/`
- Refresh trang web

### Lỗi CORS
- Backend đã được cấu hình CORS cho tất cả origins
- Nếu vẫn lỗi, kiểm tra firewall/antivirus

---

**Chúc bạn duyệt web an toàn! 🛡️**
