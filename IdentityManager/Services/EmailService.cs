using IdentityManager.Settings;
using Microsoft.Extensions.Options;
using System.Net.Mail;
using System.Net;

namespace IdentityManager.Services
{
    public class EmailService : IEmailService
    {
        private readonly IOptions<SmtpSettings> smtpSettings;

        public EmailService(IOptions<SmtpSettings> smtpSettings)
        {
            this.smtpSettings = smtpSettings;
        }
        public async Task SendAsync(string from, string to, string subject, string body)
        {
            // Send Email
            var message = new MailMessage(from, to, subject, body);

            using (var emailClient = new SmtpClient(smtpSettings.Value.Host, smtpSettings.Value.Port))
            {
                emailClient.Credentials = new NetworkCredential(smtpSettings.Value.UserName, smtpSettings.Value.Password);
                await emailClient.SendMailAsync(message);
            }
        }
    }
}
