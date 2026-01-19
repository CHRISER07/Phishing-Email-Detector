# 🔒 Phishing Email Detector

A comprehensive email security analyzer that detects phishing attempts, malicious URLs, and suspicious IP addresses using VirusTotal API integration. Built with Streamlit for an intuitive user interface.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/streamlit-1.28.0-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ✨ Features

- **📧 Multi-Provider Email Support**: Connect to Gmail, Outlook, and Yahoo accounts
- **🔍 Deep Email Scanning**: Automatically extract and analyze URLs and IP addresses from email content
- **🛡️ VirusTotal Integration**: Real-time threat detection using VirusTotal's comprehensive database
- **📊 Interactive Dashboard**: Visualize threat statistics and trends over time
- **📜 Malicious History Tracking**: Keep records of all detected threats
- **📄 Report Generation**: Export detailed reports in CSV and DOCX formats
- **🚨 Security Alerts**: Send automated email notifications for detected threats
- **🔗 URL Sandbox Viewer**: Preview suspicious links safely in an isolated environment

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- VirusTotal API key ([Get one free here](https://www.virustotal.com/gui/my-apikey))
- Email app password for Gmail ([Setup guide](https://support.google.com/accounts/answer/185833))

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/CHRISER07/Phishing-Email-Detector.git
   cd Phishing-Email-Detector
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   # Copy the example environment file
   copy .env.example .env  # Windows
   cp .env.example .env    # macOS/Linux
   ```

5. **Edit `.env` file** with your credentials:
   ```env
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ALERT_EMAIL=your_email@gmail.com
   ALERT_EMAIL_PASSWORD=your_app_password_here
   ```

### Running the Application

```bash
streamlit run app.py
```

The application will open in your default browser at `http://localhost:8501`

## 📖 Usage Guide

### 1. Analyze Emails

1. Navigate to **"Analyze Emails"** page
2. Enter your email address and app password
3. Select your email provider (Gmail, Outlook, or Yahoo)
4. Choose the number of emails to fetch (1-10)
5. Click **"Fetch & Deep Scan Emails"**
6. Review the scan results showing malicious URLs and IPs

### 2. View Malicious History

- Navigate to **"Malicious History"** to see all detected threats
- Download the history as CSV for further analysis

### 3. Detailed Reports

- Select specific emails from the dropdown to view detailed VirusTotal scan results
- See individual URL and IP analysis with threat scores

### 4. Security Dashboard

- View statistics: total threats, unique malicious URLs/IPs
- Analyze detection timeline with interactive charts
- Generate and download comprehensive reports (CSV/DOCX)

### 5. URL Sandbox (Optional)

- Navigate to the Sandbox page via Streamlit's page selector
- Preview suspicious URLs safely without direct navigation

## 🏗️ Project Structure

```
phishing-email-detector/
├── src/
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py          # Configuration management
│   ├── services/
│   │   ├── __init__.py
│   │   ├── email_service.py     # Email fetching
│   │   ├── virustotal_service.py # VirusTotal API
│   │   └── alert_service.py     # Email alerts
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── email_parser.py      # Email parsing
│   │   └── data_handler.py      # Data management
│   └── pages/
│       ├── __init__.py
│       └── sandbox.py           # URL viewer
├── app.py                        # Main application
├── .env.example                  # Environment template
├── .gitignore                    # Git ignore rules
├── requirements.txt              # Dependencies
└── README.md                     # This file
```

## 🔐 Security Best Practices

### ⚠️ Important Security Notes

1. **Never commit `.env` file** - It contains sensitive credentials
2. **Use app passwords** - Don't use your main email password
3. **Rotate API keys** - If accidentally exposed, regenerate immediately
4. **Review permissions** - Only grant necessary email access scopes

### Setting Up Gmail App Password

1. Enable 2-Factor Authentication on your Google account
2. Go to [Google Account Security](https://myaccount.google.com/security)
3. Select "2-Step Verification" → "App passwords"
4. Generate a new app password for "Mail"
5. Use this 16-character password in your `.env` file

## 🛠️ Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `VIRUSTOTAL_API_KEY` | Your VirusTotal API key | Yes |
| `ALERT_EMAIL` | Email for sending alerts | Optional |
| `ALERT_EMAIL_PASSWORD` | App password for alert email | Optional |

### Supported Email Providers

- **Gmail**: `imap.gmail.com`
- **Outlook**: `imap-mail.outlook.com`
- **Yahoo**: `imap.mail.yahoo.com`

## 📊 Features in Detail

### VirusTotal Integration

The application uses VirusTotal's API v3 to scan:
- **URLs**: Checks web links against 70+ security vendors
- **IP Addresses**: Analyzes IP reputation and threat history

### Report Generation

Generate comprehensive security reports including:
- Sender information and timestamps
- Detected malicious URLs and IPs
- Threat status (Malicious/Suspicious/Harmless)
- Visual charts and statistics

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for their comprehensive threat intelligence API
- [Streamlit](https://streamlit.io/) for the amazing web framework
- All contributors and users of this project

## 📧 Support

If you encounter any issues or have questions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review the documentation

## 🔄 Version History

### v2.0.0 (Current)
- Complete refactoring with modular architecture
- Improved security with environment variable configuration
- Enhanced UI/UX with better visualizations
- Added comprehensive documentation

### v1.0.0
- Initial release with basic phishing detection

---

**⚠️ Disclaimer**: This tool is for educational and security research purposes. Always ensure you have permission to scan emails and use the VirusTotal API responsibly within their rate limits.
