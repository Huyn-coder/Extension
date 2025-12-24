# 🛡️ PhishShield Extension

**AI-Powered Phishing Detection Browser Extension**

PhishShield là một extension Chrome sử dụng Machine Learning để phát hiện và cảnh báo các trang web lừa đảo (phishing) trong thời gian thực.

## ✨ Tính năng

- **🔍 Phát hiện phishing thời gian thực** - Tự động quét URL khi bạn duyệt web
- **🤖 AI/ML Model** - Sử dụng Random Forest với 23 features để phân tích URL
- **⚠️ Cảnh báo trực quan** - Badge màu và popup hiển thị mức độ nguy hiểm
- **🔗 Quét links trên trang** - Phát hiện các links nguy hiểm trên mọi trang web
- **📝 Báo cáo URL** - Người dùng có thể báo cáo các URL đáng ngờ
- **✅ Whitelist/Blacklist** - Quản lý các trang web tin cậy và đen

## 🚀 Cài đặt

### Bước 1: Khởi động Backend Server

```bash
cd backend
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

Hoặc sử dụng script:
```bash
cd backend
./start.sh
```

### Bước 2: Cài đặt Extension

1. Mở Chrome và truy cập `chrome://extensions/`
2. Bật **Developer mode** (góc trên bên phải)
3. Click **Load unpacked**
4. Chọn thư mục `Extension` (thư mục này)
5. Extension sẽ xuất hiện với icon 🛡️

## 📖 Hướng dẫn sử dụng

### Xem trạng thái URL hiện tại
- Click vào icon PhishShield trên thanh toolbar
- Xem kết quả phân tích với Risk Score và mức độ nguy hiểm

### Mức độ nguy hiểm
| Badge | Mức độ | Mô tả |
|-------|--------|-------|
| ✓ (xanh) | Safe | Trang web an toàn |
| ! (vàng) | Suspicious | Có dấu hiệu đáng ngờ |
| ✗ (đỏ) | Malicious | Có khả năng cao là phishing |

### Các nút chức năng
- **🔄 Re-scan URL** - Quét lại URL hiện tại
- **✓ Trust Site** - Thêm vào whitelist
- **✗ Block Site** - Thêm vào blacklist  
- **⚠️ Report as Phishing** - Báo cáo URL đáng ngờ
- **🔍 Scan All Links** - Quét tất cả links trên trang

## ⚙️ Cấu hình

Chỉnh sửa file `config.js` để thay đổi API URL:

```javascript
const PHISHSHIELD_CONFIG = {
  // Thay đổi URL nếu backend chạy ở server khác
  API_URL: "http://localhost:8000",
  
  // Các cài đặt khác...
};
```

## 🔧 API Endpoints

| Endpoint | Method | Mô tả |
|----------|--------|-------|
| `/api/check-url` | POST | Kiểm tra URL có phải phishing |
| `/api/report-url` | POST | Báo cáo URL đáng ngờ |
| `/api/whitelist` | POST | Thêm URL vào whitelist |
| `/api/blacklist` | POST | Thêm URL vào blacklist |
| `/` | GET | Health check |

## 📁 Cấu trúc thư mục

```
Extension/
├── manifest.json      # Chrome extension manifest
├── config.js          # API configuration
├── popup.html         # Popup UI
├── popup.js           # Popup logic
├── background.js      # Service worker
├── content.js         # Content script
├── content.css        # Content styles
├── icon16.png         # Icons
├── icon48.png
├── icon128.png
└── README.md          # This file
```

## 🛠️ Phát triển

### Yêu cầu
- Chrome Browser 88+
- Python 3.8+ (cho backend)
- MongoDB (tùy chọn, cho whitelist/blacklist)

### Debug
1. Mở `chrome://extensions/`
2. Click "Inspect views: service worker" để debug background script
3. Click popup và F12 để debug popup
4. F12 trên trang web để debug content script

## 📝 License

MIT License

## 👥 Team

PhishShield - Phishing Detection Project
