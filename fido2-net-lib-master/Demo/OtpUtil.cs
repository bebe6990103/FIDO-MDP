using System;
using System.Net;
using System.Net.Mail;

namespace Fido2Demo
{
    public static class OtpUtil
    {
        private static readonly Random _rng = new();

        // 產生指定長度的OTP，預設6碼
        public static string GenerateOtp(int digits = 6)
        {
            return _rng.Next((int)Math.Pow(10, digits - 1), (int)Math.Pow(10, digits)).ToString();
        }

        // 寄送OTP到指定Email
        public static void SendOtpEmail(string email, string otp)
        {
            using var smtp = new SmtpClient("smtp.gmail.com", 587)
            {
                // 填上  SMTP PASSWORD
                Credentials = new NetworkCredential("611235113@gms.ndhu.edu.tw", "Gmial application password here"),
                EnableSsl = true
            };

            var msg = new MailMessage("611235113@gms.ndhu.edu.tw", email)
            {
                Subject = "Your OTP code",
                Body = $"Your OTP code is: {otp}\n\nThis code will expire in 3 minutes."
            };

            smtp.Send(msg);
        }
    }
}