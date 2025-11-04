package email

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/smtp"
	"os"
	"time"
)

type EmailType string

const (
	EmailTypeWelcome        EmailType = "welcome"
	EmailTypeForgotPassword EmailType = "forgot_password"
	EmailTypePasswordReset  EmailType = "password_reset"
)

type EmailJob struct {
	To       string
	Subject  string
	Type     EmailType
	Data     map[string]interface{}
	Priority int
}

type EmailService struct {
	queue      chan EmailJob
	smtpHost   string
	smtpPort   string
	smtpUser   string
	smtpPass   string
	fromEmail  string
	fromName   string
	workerPool int
}

func NewEmailService() *EmailService {
	service := &EmailService{
		queue:      make(chan EmailJob, 100), // Buffer of 100 emails
		smtpHost:   getEnv("SMTP_HOST", "smtp.gmail.com"),
		smtpPort:   getEnv("SMTP_PORT", "587"),
		smtpUser:   getEnv("SMTP_USER", ""),
		smtpPass:   getEnv("SMTP_PASS", ""),
		fromEmail:  getEnv("FROM_EMAIL", "noreply@example.com"),
		fromName:   getEnv("FROM_NAME", "MyApp"),
		workerPool: 3, // 3 concurrent workers
	}

	// Start background workers
	for i := 0; i < service.workerPool; i++ {
		go service.worker(i)
	}

	log.Printf("Email service started with %d workers", service.workerPool)
	return service
}

func (s *EmailService) SendWelcomeEmail(to, firstName string) {
	job := EmailJob{
		To:      to,
		Subject: "Welcome to MyApp!",
		Type:    EmailTypeWelcome,
		Data: map[string]interface{}{
			"FirstName": firstName,
			"AppURL":    getEnv("APP_URL", "http://localhost:3000"),
		},
		Priority: 1,
	}
	s.enqueue(job)
}

func (s *EmailService) SendForgotPasswordEmail(to, firstName, resetToken string) {
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", getEnv("APP_URL", "http://localhost:3000"), resetToken)
	
	job := EmailJob{
		To:      to,
		Subject: "Reset Your Password",
		Type:    EmailTypeForgotPassword,
		Data: map[string]interface{}{
			"FirstName": firstName,
			"ResetURL":  resetURL,
			"ExpiresIn": "1 hour",
		},
		Priority: 0, // High priority
	}
	s.enqueue(job)
}

func (s *EmailService) SendPasswordResetConfirmation(to, firstName string) {
	job := EmailJob{
		To:      to,
		Subject: "Password Changed Successfully",
		Type:    EmailTypePasswordReset,
		Data: map[string]interface{}{
			"FirstName": firstName,
			"Timestamp": time.Now().Format("January 2, 2006 at 3:04 PM"),
		},
		Priority: 1,
	}
	s.enqueue(job)
}

func (s *EmailService) enqueue(job EmailJob) {
	select {
	case s.queue <- job:
		log.Printf("Email queued: %s to %s", job.Type, job.To)
	default:
		log.Printf("Email queue full, dropping email to %s", job.To)
	}
}

func (s *EmailService) worker(id int) {
	log.Printf("Email worker %d started", id)
	for job := range s.queue {
		log.Printf("Worker %d processing email: %s to %s", id, job.Type, job.To)
		
		if err := s.send(job); err != nil {
			log.Printf("Worker %d failed to send email to %s: %v", id, job.To, err)
			// In production, implement retry logic here
		} else {
			log.Printf("Worker %d successfully sent email to %s", id, job.To)
		}
		
		// Small delay to prevent overwhelming SMTP server
		time.Sleep(100 * time.Millisecond)
	}
}

func (s *EmailService) send(job EmailJob) error {
	// Skip if SMTP is not configured
	if s.smtpUser == "" || s.smtpPass == "" {
		log.Printf("SMTP not configured, simulating email send to %s", job.To)
		return nil
	}

	// Get email template
	htmlBody, err := s.getTemplate(job.Type, job.Data)
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	// Prepare email message
	message := s.buildMessage(job.To, job.Subject, htmlBody)

	// Send email
	auth := smtp.PlainAuth("", s.smtpUser, s.smtpPass, s.smtpHost)
	addr := fmt.Sprintf("%s:%s", s.smtpHost, s.smtpPort)
	
	err = smtp.SendMail(addr, auth, s.fromEmail, []string{job.To}, []byte(message))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (s *EmailService) buildMessage(to, subject, htmlBody string) string {
	headers := make(map[string]string)
	headers["From"] = fmt.Sprintf("%s <%s>", s.fromName, s.fromEmail)
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + htmlBody

	return message
}

func (s *EmailService) getTemplate(emailType EmailType, data map[string]interface{}) (string, error) {
	var tmplStr string

	switch emailType {
	case EmailTypeWelcome:
		tmplStr = welcomeTemplate
	case EmailTypeForgotPassword:
		tmplStr = forgotPasswordTemplate
	case EmailTypePasswordReset:
		tmplStr = passwordResetTemplate
	default:
		return "", fmt.Errorf("unknown email type: %s", emailType)
	}

	tmpl, err := template.New("email").Parse(tmplStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (s *EmailService) Close() {
	log.Println("Shutting down email service...")
	close(s.queue)
}

func GenerateResetToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

const welcomeTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">Welcome to MyApp!</h1>
    </div>
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
        <h2 style="color: #667eea;">Hi {{.FirstName}}! 👋</h2>
        <p>Thank you for joining MyApp! We're excited to have you on board.</p>
        <p>Your account has been successfully created and you're ready to get started.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.AppURL}}" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Get Started</a>
        </div>
        <p>If you have any questions, feel free to reach out to our support team.</p>
        <p>Best regards,<br>The MyApp Team</p>
    </div>
    <div style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
        <p>© 2025 MyApp. All rights reserved.</p>
    </div>
</body>
</html>
`

const forgotPasswordTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Reset Password</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">Reset Your Password</h1>
    </div>
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
        <h2 style="color: #f5576c;">Hi {{.FirstName}},</h2>
        <p>We received a request to reset your password. Click the button below to create a new password:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.ResetURL}}" style="background: #f5576c; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
        </div>
        <p style="color: #666; font-size: 14px;">This link will expire in {{.ExpiresIn}}.</p>
        <p style="color: #666; font-size: 14px;">If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0;">
            <strong>Security Tip:</strong> Never share this link with anyone. Our team will never ask for your password.
        </div>
        <p>Best regards,<br>The MyApp Team</p>
    </div>
    <div style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
        <p>© 2025 MyApp. All rights reserved.</p>
    </div>
</body>
</html>
`

const passwordResetTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Changed</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">Password Changed Successfully</h1>
    </div>
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
        <h2 style="color: #43e97b;">Hi {{.FirstName}},</h2>
        <p>Your password has been successfully changed on {{.Timestamp}}.</p>
        <div style="background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin: 20px 0;">
            <strong>✓ All Set!</strong> Your account is secure with your new password.
        </div>
        <p style="color: #666; font-size: 14px;">If you didn't make this change, please contact our support team immediately.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.AppURL}}" style="background: #43e97b; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Go to Dashboard</a>
        </div>
        <p>Best regards,<br>The MyApp Team</p>
    </div>
    <div style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
        <p>© 2025 MyApp. All rights reserved.</p>
    </div>
</body>
</html>`