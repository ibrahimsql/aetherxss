# AetherXSS Scanner

Advanced Cross-Site Scripting (XSS) Scanner with Docker Integration

---

## 🚀 Features

- 🔍 Advanced XSS payload detection
- 🩸 Basic Another Vulnerability (BAV) Scan support
- 🎯 Multiple scanning methods (GET, POST, Headers)
- 🕷️ Web crawling capability
- 🎨 Animated, user-friendly CLI UI
- 🐳 Docker support
- 📊 Detailed HTML & JSON reports
- 🔄 Multi-threading support
- 🔒 Custom payload support
- 🌐 Proxy support
- 📝 Verbose logging
- ⚔️ Auto-exploitation
- 🧪 DOM-based XSS detection
- 🕵️‍♂️ Blind XSS testing
- 🧩 Framework-specific payloads (Angular, React, Vue, jQuery)
- 🛡️ WAF Detection & Bypass
- 🕸️ Parameter discovery
- 🔄 CSP analysis & bypass

---

## 🐳 Quick Start with Docker

```bash
# Build and run with docker-compose
docker-compose up --build

# Or run directly with Docker
docker build -t aetherxss .
docker run -v $(pwd)/reports:/app/reports aetherxss --url https://target.com
```

---

## 🛠️ Installation (Without Docker)

```bash
# Install .NET 7.0 SDK (if not already installed)
dotnet restore
dotnet build
dotnet run -- --url https://target.com
```

---

## ⚡ Usage

```bash
AetherXSS --url <target_url> [options]

  --url <url>                Target URL to scan (required)
  --no-color                 Disable colored output
  --proxy <proxy_url>        Use proxy for requests
  --cookie <cookie_data>     Use custom cookies
  --headers <h1:v1,...>      Use custom HTTP headers
  --user-agent <ua>          Use specific User-Agent
  --wordlist <file>          Load custom payload list
  --threads <num>            Number of concurrent threads (default: 5)
  --delay <ms>               Delay between requests (milliseconds)
  --timeout <sec>            Request timeout (seconds, default: 30)
  --output <file>            Save results to file
  --verbose                  Show detailed output
  --dom-scan                 Enable DOM-based XSS scanning
  --crawl                    Crawl website for additional URLs
  --depth <num>              Crawl depth (default: 2)
  --params                   Test common parameter names
  --methods                  Test different HTTP methods
  --fuzz-headers             Fuzz HTTP headers for XSS
  --auto-exploit             Attempt to automatically exploit found vulnerabilities
  --framework-specific       Enable Angular/React/Vue/jQuery payloads
  --blind-xss                Enable Blind XSS testing
  --blind-callback <url>     Callback URL for Blind XSS detection
  --csp-analysis             Enable Content Security Policy analysis and bypass
  --use-bav                  Enable Boundary Value Analysis (BAV) testing
  --skip-bav                 Skip Boundary Value Analysis (BAV) testing
  --help                     Show this help message
```

---

## 📁 Directory Structure

```
.
├── AetherXSS.cs            # Main scanner code
├── VulnerabilityTests.cs   # Unit and integration tests for vulnerability scanning
├── RequestLogger.cs        # Handles logging of HTTP requests and responses
├── VulnerabilityFinding.cs # Data structure/model for storing vulnerability findings
├── AetherXSS.csproj        # Project file
├── Dockerfile              # Docker configuration
├── docker-compose.yml      # Docker Compose configuration
├── reports/                # Scan reports directory
├── wordlists/              # Custom wordlists directory
└── custom_payloads/        # Custom XSS payloads directory
```

---

## 🧪 Testing & Development Notes

- **VulnerabilityTests.cs**: Contains unit and integration tests for all core functionalities. These tests ensure the tool operates safely and correctly.
- **RequestLogger.cs**: Handles detailed logging of all HTTP requests and responses. This facilitates tracking actions and discovered vulnerabilities.
- **VulnerabilityFinding.cs**: Data model for storing details of discovered vulnerabilities. Used for reporting and analysis.

To run or add new tests, refer to the `VulnerabilityTests.cs` file.

---

## 📦 Required Dependencies

- .NET 7.0 SDK
- Newtonsoft.Json
- HtmlAgilityPack
- Selenium.WebDriver
- Microsoft.Playwright
- Serilog
- Spectre.Console

---

## ⚠️ Security Notes

- **Always obtain permission before scanning any website.**
- Use with caution on production systems.
- Consider using a proxy for anonymity.
- Review and customize payloads before use.

---

![screenshot](https://github.com/user-attachments/assets/e0d15e88-9da1-4dae-83e0-4ed1ae774f44)

---

## 🫂 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please update/add tests as appropriate.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🤝 Developed by

- 👨‍💻 [@ibrahimsql](https://github.com/ibrahimsql)
- 📧 Email: ibrahimsql@proton.me
- 🌍 https://github.com/ibrahimsql
- 🏆 Cyber Security Engineer | OSCP Candidate | Ethical Hacking Specialist | Penetration Testing Expert | Red Team & Security Research Professional | Passionate About Defending the Digital World

- ☕ Always fueled by coffee & curiosity!
- 💬 Feel free to reach out for collaboration or just to say hi!
