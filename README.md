## HdrX - Email Header Analyzer

A Python-based email header analysis tool designed to detect phishing attempts by examining email headers. HdrX helps identify suspicious patterns and anomalies in email headers to protect against phishing attacks.

### Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Analyzing Email Headers](#analyzing-email-headers)
  - [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)

---

### Introduction

HdrX is a command-line tool that provides a comprehensive analysis of email headers, which is a vital step in detecting phishing attacks and email spoofing. By analyzing key header fields, it can identify suspicious patterns that indicate a malicious intent. This tool is designed for both individuals and organizations seeking to enhance their email security posture.

---

### Features

*   **Header Extraction:** Extracts email headers from raw email content.
*  **Header Parsing:** Parses and prints the email headers.
*   **From Header Analysis:** Checks the `From` header for spoofing.
*   **Received Header Analysis:** Analyzes the `Received` headers for suspicious hostnames.
*   **Reply-To Analysis:** Checks the `Reply-To` header for inconsistencies.
*   **SPF, DKIM, and DMARC checks:** Verifies SPF, DKIM, and DMARC records for domain authentication.
*  **Keyword Analysis:** Uses a dynamic list of keywords and regexes to identify suspicious content.
*   **Customizable Keyword Lists:** Uses an external JSON file, allowing for easy updates to the keywords.
*   **Clear output:** Present parsed headers and analysis results, with a phishing risk score.
*   **Comprehensive Error Handling:** Includes try-except blocks and clear log messages.
*  **Modularity:** The code is structured into abstract classes, to make it easier to maintain and to add new functionalities.

---

### Installation

To use HdrX locally, follow these steps:

#### 1. Clone the Repository

```bash
git clone https://github.com/CodeByKalvin/HdrX.git
cd HdrX
```

#### 2. Install Dependencies

Make sure you have **Python 3.6 or higher** installed. Install the required dependencies using `pip`:

```bash
pip install -r requirements.txt
```

The `requirements.txt` should contain the following:
```txt
requests
dmarc
```

---

### Usage

Once installed, you can run the application from the command line using:

```bash
python email_analyzer.py
```

#### Analyzing Email Headers

To analyze email headers, you can either pass an email file path or pipe the email content to the script:

1.  **From File:**
    ```bash
    python email_analyzer.py -f email.txt
    ```

2.  **From Standard Input (Piped):**
    ```bash
    cat email.txt | python email_analyzer.py
    ```
    Or copy and paste directly to the terminal.

The tool will output the email headers, the analysis results with a score, and if the score is high, a warning message.

#### Configuration

1.  **Keyword List:** The tool uses an external file `keywords.json` that should be created in the same directory.
2.  **Modify keywords:** Modify this file to add or change the keywords and regexes used in the application.
    *  **Structure**: The `keywords.json` file is a JSON object with the following categories:
         *  **`general`**:  A list of generic keywords.
         *  **`personal`**: A list of keywords related to personal information.
         *  **`company`**: Keywords related to company departments, that might be used in internal phishing attacks
         * **`url`**: List of regexes for detecting suspicious URLs.
         * **`financial`**: Keywords related to financial actions.
         * **`email_specific`**: Keywords related to problems sending or receiving emails.

---

### Project Structure

```
hdrx/
│
├── email_analyzer.py         # Main Python script for running the CLI app
├── README.md                 # This README file
├── requirements.txt          # List of dependencies
└── keywords.json            # File for storing keywords and regexes
```

---

### Requirements

-   **Python 3.6 or higher**
-   **Pip** to install dependencies
-   Required Python libraries (in `requirements.txt`):
    -   `requests`: For HTTP calls to webhooks and push notifications.
    -   `dmarc`: For validating SPF, DKIM and DMARC records.

To install the dependencies:

```bash
pip install -r requirements.txt
```

---

### Contributing

Contributions are welcome! Feel free to submit pull requests or create an issue to report a bug or request new features.

#### Steps to Contribute:

1. Fork the repository.
2. Create a new branch for your feature (`git checkout -b feature-name`).
3. Make your changes.
4. Test your changes.
5. Commit your changes (`git commit -m 'Add some feature'`).
6. Push to your branch (`git push origin feature-name`).
7. Create a pull request.

---

### License

This project is open-source and available under the [MIT License](LICENSE).

---

### Future Improvements

*   Implement more advanced techniques to detect spoofed emails.
*   Incorporate machine learning for dynamic and adaptive detection patterns.
*   Integrate with external threat intelligence services.
*   Develop a GUI for better user interaction.

---

### Authors

-   **CodeByKalvin** - *Initial work* - [GitHub Profile](https://github.com/codebykalvin)
