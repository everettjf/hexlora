# Hexlora

[Discord](https://discord.gg/eGzEaP6TzR)

[English](README.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md) · [한국어](README.ko.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Español](README.es.md) · [Italiano](README.it.md) · [Português (Brasil)](README.pt-BR.md) · [Русский](README.ru.md) · **Tiếng Việt**

Hexlora là công cụ đa nền tảng viết bằng Rust để phân loại tĩnh, so sánh và kiểm tra bản phát hành của ứng dụng và tệp nhị phân. Công cụ biểu diễn ứng dụng, thư mục, gói và từng tệp thành các sản phẩm logic, rồi kiểm tra cấu trúc, siêu dữ liệu, chữ ký, phần phụ thuộc cùng thông tin PE, Mach-O và ELF mà không chạy nội dung.

Ứng dụng cung cấp bản đồ cây kích thước tương tác, biểu đồ và bản đồ nhiệt entropy liên kết với trình xem Hex, đồ thị phụ thuộc, dòng thời gian chữ ký, ma trận kiến trúc và quyền riêng tư IPA, bộ lọc mức độ nghiêm trọng, bảng điều khiển có thể đổi kích thước và chế độ tương phản cao. Có thể xuất báo cáo Markdown, PDF, SVG và ảnh chụp cửa sổ.

README tiếng Anh là nguồn chính thức và chứa ma trận hỗ trợ chi tiết. Bản dịch này tóm tắt cách cài đặt, tính năng chính và giới hạn an toàn.

## Ngôn ngữ giao diện

Hexlora hỗ trợ tiếng Anh, Trung giản thể, Nhật, Hàn, Đức, Pháp, Tây Ban Nha, Ý, Bồ Đào Nha Brazil, Nga và Việt. Menu ngôn ngữ trên thanh menu hoặc dưới cửa sổ chuyển giao diện ngay lập tức và lưu lựa chọn cho lần mở sau. Lần đầu mở ứng dụng sẽ dùng ngôn ngữ hệ thống. Điều hướng, nút, tiêu đề bảng điều khiển và các tiêu đề bảng thường dùng đã được dịch. Nội dung sản phẩm, chẩn đoán kỹ thuật và báo cáo xuất ra giữ nguyên văn bản gốc.

## Ảnh chụp màn hình

[![Hexlora đang kiểm tra Hexlora.app](docs/assets/screenshots/overview.jpg)](https://xnu.app/hexlora/vi/#gallery)

Thư viện ảnh giới thiệu cấu trúc ứng dụng, thông tin Mach-O, phần phụ thuộc, chuỗi đã trích xuất và trình xem Hex đọc theo phạm vi giới hạn.

## Cài đặt bằng Homebrew

```sh
brew install --cask everettjf/tap/hexlora
```

Công cụ dòng lệnh tùy chọn:

```sh
brew install everettjf/tap/hexlora-cli
```

Ứng dụng macOS được ký bằng Developer ID, được Apple công chứng và đính kèm vé công chứng. Mỗi bản phát hành kiểm tra chữ ký nghiêm ngặt, xác thực vé và đánh giá Gatekeeper.

## Tính năng chính

| Lĩnh vực | Hỗ trợ hiện tại |
|---|---|
| macOS / iOS | Ứng dụng macOS, bundle, framework, Mach-O đa kiến trúc, DMG và PKG/XAR; kiểm tra IPA về định danh, kích thước, đối tượng nhúng, kiến trúc, ngôn ngữ, quyền riêng tư, hồ sơ cấp phép, quyền và phát hiện. |
| Android | Manifest APK, thông tin gói và SDK, quyền, thành phần công khai, liên kết sâu, thống kê DEX, thư viện gốc, ABI, dấu hiệu chữ ký và phát hiện. |
| Windows | Tiêu đề, phần, nhập, xuất, ký hiệu, phụ thuộc và siêu dữ liệu Authenticode PE/COFF; định danh, khả năng, ứng dụng, điểm vào và trạng thái chữ ký APPX/MSIX. |
| Linux | Tiêu đề ELF, kiến trúc, trình thông dịch, phần, đoạn, tái định vị, ký hiệu và phụ thuộc; siêu dữ liệu DEB, tệp, kích thước cài đặt, tập lệnh bảo trì và tệp có đặc quyền. |
| Vùng chứa và dữ liệu | ZIP, tar/tar.gz, ar, DMG, ISO, JSON, XML, plist, SQLite, ảnh và văn bản. 7z, RAR và luồng nén độc lập được nhận diện nhưng chưa hỗ trợ duyệt toàn bộ các tệp bên trong. |
| Phân tích chung | Cây sản phẩm, siêu dữ liệu, tiêu đề, lát kiến trúc, phần, đoạn, ký hiệu, phụ thuộc, chuỗi, xem Hex theo yêu cầu, hàm băm, entropy, chữ ký và phát hiện. |
| So sánh và CI | Định danh SHA-256 chính xác; tệp được thêm, xóa, sửa hoặc di chuyển, tăng kích thước và trùng lặp; JSON, Markdown, HTML, SARIF, chính sách phát hành, ngưỡng mức độ nghiêm trọng và mã thoát ổn định. |

[Ma trận hỗ trợ chi tiết (tiếng Anh)](README.md#detailed-support-matrix) · [Lược đồ báo cáo (tiếng Anh)](docs/report-schema.md) · [Ma trận kiểm thử (tiếng Anh)](docs/testing.md)

## Quy trình sử dụng

Mở hoặc kéo thả tệp, ứng dụng, gói, thư mục hay không gian làm việc. Đổi kích thước bảng điều khiển và duyệt các bảng lớn được hiển thị ảo hóa. Không gian làm việc lưu đường dẫn, chế độ xem, dấu trang, ghi chú và bộ nhớ đệm phân tích. Công cụ bên ngoài tương thích chỉ chạy khi được yêu cầu.

Phím tắt macOS: `⌘N` cửa sổ mới, `⌘O` tệp, `⇧⌘O` thư mục, `⌥⌘O` không gian làm việc, `⌘S` lưu, `⌘F` tìm kiếm.

## CLI

```sh
hexlora-cli inspect ./SomeApp.app --pretty
hexlora-cli inspect ./MyApp.ipa --depth deep --format sarif --output hexlora.sarif
hexlora-cli inspect ./package --hash sha256 --strings --entropy
```

Độ sâu phân tích gồm `lightweight`, `standard` và `deep`. Mã thoát: lỗi nghiêm trọng `1`, không đạt chính sách hoặc ngưỡng `2`, hủy `4`, báo cáo một phần còn dùng được `5`.

## Nền tảng và yêu cầu

macOS 13 Ventura trở lên trên Apple silicon (`arm64`), Windows x64 hoặc Linux amd64. Các lệnh cài đặt macOS ở trên cần Homebrew.

GitHub Releases cung cấp MSI và ZIP di động cho Windows, DEB và tar.gz di động cho Linux. Các gói Windows và Linux hiện chưa có chữ ký mã; hãy kiểm tra SHA256SUMS trước khi cài đặt. Bộ phân tích kiểm tra PE và ELF trên mọi nền tảng được hỗ trợ.

[Tải xuống](https://github.com/everettjf/hexlora/releases/latest) · [SHA256SUMS](https://github.com/everettjf/hexlora/releases/latest/download/SHA256SUMS)

## Giới hạn an toàn

Hexlora phân tích tĩnh và chỉ đọc. Công cụ không chạy chương trình nhập vào, gắn ảnh đĩa, cài gói hay tự động giải nén kho lưu trữ. Công cụ không dịch ngược, gỡ lỗi hoặc thay đổi byte. Liên kết tượng trưng không được duyệt theo. Đầu vào, đệ quy, số tệp, chuỗi và đầu ra lệnh đều có giới hạn rõ ràng. Phát hiện bằng quy tắc kinh nghiệm là gợi ý, không phải kết luận về mã độc.

## Kiểm chứng tự động

CI kiểm tra workspace Rust, Clippy, phiên bản Rust tối thiểu 1.88, quy ước CLI và báo cáo, cùng quá trình dựng và mở ứng dụng macOS. Bộ dữ liệu công khai được cố định theo kích thước và SHA-256 gồm 16 sản phẩm thực tế. Các bản phát hành macOS còn kiểm tra Developer ID, công chứng Apple, vé, Gatekeeper, cài đặt Homebrew và kiểm thử Formula.

## Tài liệu

[Chiến lược sản phẩm](docs/product-strategy.md) · [Ma trận hỗ trợ chi tiết (tiếng Anh)](README.md#detailed-support-matrix) · [Lược đồ báo cáo (tiếng Anh)](docs/report-schema.md) · [Ma trận kiểm thử (tiếng Anh)](docs/testing.md) · [Trang web](https://xnu.app/hexlora/vi/)
