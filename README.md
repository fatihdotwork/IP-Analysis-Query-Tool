# IP Analysis & Query Tool

A versatile, multi-threaded desktop application for analyzing lists of IP addresses. This tool allows security analysts, network administrators, and researchers to quickly perform DNS/ASN lookups, check against the Spamhaus blacklist, and query the AbuseIPDB API for detailed reputation information.

[ss1](https://raw.githubusercontent.com/fatihdotwork/IP-Analysis-Query-Tool/refs/heads/main/ss1.JPG)

https://raw.githubusercontent.com/fatihdotwork/IP-Analysis-Query-Tool/refs/heads/main/ss2.JPG

https://raw.githubusercontent.com/fatihdotwork/IP-Analysis-Query-Tool/refs/heads/main/ss3.JPG


## ✨ Features

-   **Multi-Tab Interface**: Separate, organized tabs for different types of queries.
-   **Concurrent Queries**: Utilizes multi-threading to process large IP lists quickly. Users can select the number of concurrent threads.
-   **DNS & ASN Lookup**: Retrieves Hostname (PTR Record), ASN (Autonomous System Number), and ISP information for each IP.
-   **Spamhaus Lookup**: Checks IPs against the `zen.spamhaus.org` DNS blocklist.
-   **AbuseIPDB Integration**: Queries the AbuseIPDB API to get detailed reports, including confidence score, total report count, country, and domain.
-   **Interactive Controls**: Start, Pause, Resume, and Stop controls for managing the query process.
-   **Live Progress Tracking**: Real-time progress bars show the status with percentage and a counter (`Processed / Total`).
-   **Dynamic Results Table**: View results as they come in. Columns can be sorted by clicking on the headers.
-   **Data Export**: Save the results from each tab into a formatted `.txt` file.
-   **Multi-Language Support**: The user interface supports both English (default) and Turkish.

---

## 🛠️ Requirements

-   Python 3.6+
-   Required Python libraries: `requests`, `ipwhois`

---

## 🚀 Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/fatihdotwork/IP-Analysis-Query-Tool.git
    cd IP-Analysis-Query-Tool
    ```

2.  **Install the required libraries:**
    Create a `requirements.txt` file with the following content:
    ```
    requests
    ipwhois
    ```
    Then, run the following command in your terminal:
    ```bash
    pip install -r requirements.txt
    ```

---

## 🏃‍♂️ How to Run

1.  Ensure you have Python and the required libraries installed.
2.  Run the application from your terminal:
    ```bash
    python ip_analyzer_app.py
    ```
    *(Assuming you named the file `ip_analyzer_app.py`)*

---

## 📋 How to Use

1.  **Launch the application.**
2.  **(Optional)** Go to `File -> Language` to switch the UI language between English and Turkish.
3.  Click the **"Load IP List (.txt)"** button to load a text file containing one IP address per line.
4.  Navigate to the desired tab (DNS, Spamhaus, or AbuseIPDB).
5.  **For AbuseIPDB**: Enter your API key in the designated field. You can get a free API key from the [AbuseIPDB website](https://www.abuseipdb.com/account/api).
6.  Select the number of concurrent queries you want to run.
7.  Click the **"Start"** button to begin the process.
8.  You can **Pause/Resume** or **Stop** the process at any time using the control buttons.
9.  Once the query is complete, click the **"Save Results"** button to export the data to a text file.

---

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
