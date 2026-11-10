// Gửi email bằng Gmail của bạn (không cần tên miền). Dán vào https://script.google.com -> Dự án mới.
// Deploy > New deployment > Web app > Execute as: Me, Who has access: Anyone > Deploy, rồi copy "Web app URL".
// Đặt SECRET giống giá trị MAIL_WEBHOOK_SECRET trên Worker. Gói Gmail thường gửi được khoảng 100 email / ngày.
const SECRET = "ĐỔI_THÀNH_MỘT_CHUỖI_BÍ_MẬT_DÀI";

function doPost(e) {
  try {
    const d = JSON.parse(e.postData.contents);
    if (d.secret !== SECRET) return ContentService.createTextOutput("DENIED");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(d.to))) return ContentService.createTextOutput("BAD");
    MailApp.sendEmail({ to: String(d.to), subject: String(d.subject).slice(0, 100), body: String(d.text).slice(0, 2000), name: "Melochi4Luna" });
    return ContentService.createTextOutput("OK");
  } catch (err) {
    return ContentService.createTextOutput("ERR");
  }
}
