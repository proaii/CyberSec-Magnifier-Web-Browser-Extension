# Threat Magnifier (CyberSec-Magnifier-Web-Browser-Extension)

**Version:** 2.0  
**Project:** CPE393 Mini Project

Threat Magnifier is a browser extension that acts like a security magnifying glass. Point at web components on any page to instantly see if they pose a potential threat. It helps you identify malicious links, forms, and other potentially dangerous web elements before you interact with them.

## Features

- **Real-time Threat Analysis**: Hover over web elements to assess their security risk.
- **Advanced Mode**: Get detailed threat analysis and website previews. If disabled, a minimal color-coded flag is shown to indicate the threat level.
- **Block Dangerous Links**: Automatically prevents you from accidentally clicking links classified as high-risk or dangerous. A warning prompt gives you the option to proceed if you choose to.
- **VirusTotal Integration**: Optional integration with the VirusTotal API. Enter your API key in the extension popup to get accurate scoring for external links.
- **Bilingual Interface**: Seamlessly switch between English (EN) and Thai (TH) languages from the extension popup.

## Setup and Installation

1. **Clone or Download the Repository**:
   Download the source code to your local machine.

2. **Load the Extension into Your Browser** (e.g., Chrome/Edge/Brave):
   - Open your browser and navigate to the Extensions page (`chrome://extensions/` or `edge://extensions/`).
   - Enable **Developer mode** (usually a toggle in the top right corner).
   - Click the **Load unpacked** button.
   - Select the `threat-magnifier-extension` folder inside this project directory.

3. **Configure VirusTotal API (Optional for Advanced Scoring)**:
   - Click on the Threat Magnifier icon in your browser toolbar to open the popup.
   - Enter your VirusTotal API Key in the designated input field.
   - Click **Save Key**. The extension will now use VirusTotal to analyze external links when Advanced Mode is enabled.

## Usage

1. Click the Threat Magnifier icon in your browser toolbar.
2. Click **Start Magnifier** to activate the tool.
3. Move your mouse cursor over links, forms, and interactive elements on any web page.
4. The extension will display a security overlay:
   - **Minimal View**: Shows a colored flag (Safe, Warning, Danger).
   - **Advanced View**: Shows detailed information, threat breakdown, and external site previews (if enabled).

## Repository Structure

- `threat-magnifier-extension/`: Contains the browser extension source code.
  - `manifest.json`: Extension configuration (Manifest V3).
  - `popup.html` & `popup.js`: The user interface and logic for the extension's browser action popup.
  - `content.js` & `content.css`: Scripts and styles injected into web pages to analyze and highlight elements.
  - `scripts/`: Contains core logic for API interaction, UI overlays, and threat analysis.
  - `i18n/`: Internationalization files for English and Thai translations.
- `threat-magnifier-test-site/`: A simple HTML site designed to test the extension's capabilities against various web threats.

## License

Please refer to the `LICENSE` file in the project repository for licensing information.
