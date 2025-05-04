# AreumSec Privacy Policy

Last Updated: May 4, 2025

AreumSec is a browser extension designed to protect users by checking the safety of URLs against trusted threat intelligence sources, including URLhaus, VirusTotal, and Google Safe Browsing. We are committed to your privacy and do not collect, use, or sell any user data. This Privacy Policy explains how the extension processes data to provide its functionality, ensuring transparency and compliance with privacy standards.

## Data Processed by AreumSec

AreumSec does not collect, use, or sell any user data. The extension’s code processes the following data solely to perform URL safety checks:

- **URLs of Visited Webpages**:
  - **Purpose**: The extension accesses the URLs of webpages you visit to check their safety against URLhaus, VirusTotal, and Google Safe Browsing APIs. This is necessary to identify potential threats like malware or phishing sites.
  - **Processing**: URLs are processed locally by the extension’s code and sent to the following APIs for analysis:
    - `https://urlhaus.abuse.ch`: To check against a public database of malicious URLs.
    - `https://www.virustotal.com`: To query VirusTotal’s URL analysis (if a user-provided API key is configured).
    - `https://safebrowsing.googleapis.com`: To query Google Safe Browsing (if a user-provided API key is configured).
  - **Storage**: URLs are not stored persistently. Temporary caching in `chrome.storage.local` (browser-local storage) may occur to reduce API requests and enable offline checks. Cached data is cleared periodically and contains no personal information.
  - **Sharing**: URLs are only sent to the above APIs for safety checks. No URLs are shared with other third parties or used for any other purpose.

- **API Keys for VirusTotal and Google Safe Browsing**:
  - **Purpose**: Users may optionally provide API keys in the extension’s options page to enable VirusTotal and Google Safe Browsing checks.
  - **Processing**: API keys are stored securely in `chrome.storage.sync` (encrypted by Chrome) to persist across sessions and are used only to authenticate API requests.
  - **Storage**: Keys are stored locally in the browser and never transmitted to any servers or third parties.
  - **Sharing**: API keys are not shared or used beyond their intended purpose (authenticating API calls).

- **Cached Safety Results and URLhaus Threat Data**:
  - **Purpose**: The extension caches URL safety verdicts (e.g., `Safe`, `Malicious`) and URLhaus threat data (public malicious URLs) to improve performance and support offline checks.
  - **Processing**: Cached data is stored in `chrome.storage.local` and used by the extension’s code to display results in the popup or trigger notifications for malicious URLs.
  - **Storage**: Cache is temporary, scoped to URLs, and cleared periodically to minimize storage. No personal data is included.
  - **Sharing**: Cached data is not shared with any third parties and remains local to your browser.

## No Collection, Use, or Sale of User Data

AreumSec does not collect, use, or sell any user data. All data processing (URLs, API keys, cached results) is performed by the extension’s code for the sole purpose of checking URL safety. We do not:
- Collect personal information (e.g., names, emails, or browsing history beyond URLs).
- Store data on external servers or share it with third parties beyond the specified APIs.
- Sell or monetize any data.
- Track user behavior or create user profiles.

## Future Data Processing

If AreumSec introduces new features, we may process additional data, such as:
- **User Preferences**: Settings like notification preferences, stored in `chrome.storage.sync` to customize your experience.
- **Anonymous Usage Statistics**: Aggregated, non-identifiable metrics (e.g., number of URLs checked) to improve the extension, with user consent and opt-out options.

Any future data processing will be minimal, transparent, and require your explicit consent. We will update this Privacy Policy and notify users of changes.

## Data Security

We prioritize your privacy and security:
- **Encryption**: API keys in `chrome.storage.sync` are encrypted by Chrome’s storage system.
- **Local Processing**: All data processing occurs within your browser, except for API calls to URLhaus, VirusTotal, and Google Safe Browsing.
- **No Remote Code**: The extension uses only local code, with no scripts loaded from external sources.
- **Minimal Data**: Only URLs and necessary metadata are processed, with no access to page content, forms, or personal information.
- **Cache Management**: Temporary caches are cleared regularly to minimize data retention.

## Third-Party Services

AreumSec uses the following third-party services for URL safety checks:
- **URLhaus (`https://urlhaus.abuse.ch`)**: Provides a public database of malicious URLs. Only URLs are sent to fetch threat data.
- **VirusTotal (`https://www.virustotal.com`)**: Analyzes URLs if a user-provided API key is configured. Only URLs and the API key are sent.
- **Google Safe Browsing (`https://safebrowsing.googleapis.com`)**: Checks URLs for threats if a user-provided API key is configured. Only URLs and the API key are sent.

These services are trusted and used only for their intended purpose. We do not control their data practices, but URLs sent to them are not linked to personal data. Please review their respective privacy policies for details.

## Your Rights and Choices

You have full control over data processed by AreumSec:
- **Clear API Keys**: Remove VirusTotal or Google Safe Browsing keys via the options page.
- **Clear Cache**: Clear browser storage via browser settings or by uninstalling the extension.
- **Disable Checks**: Avoid entering API keys to skip VirusTotal or Google Safe Browsing checks.
- **Uninstall**: Remove the extension to stop all data processing.

To clear storage manually:
1. Open your browser’s developer tools (`F12` or right-click > Inspect).
2. Run in the console:
   ```javascript
   chrome.storage.local.clear();
   chrome.storage.sync.clear();
   ```
3. Verify via:
   ```javascript
   chrome.storage.local.get(null, console.log);
   chrome.storage.sync.get(null, console.log);
   ```

## Children’s Privacy

AreumSec is not directed at children under 13. We do not knowingly process data from children, and no personal data is involved in the extension’s operation.

## Changes to This Privacy Policy

We may update this Privacy Policy to reflect new features or legal requirements. The latest version will be posted on our website or linked in the Chrome Web Store listing, with the “Last Updated” date revised. Significant changes will be communicated via the extension or store listing.

## Contact Us

If you have questions about this Privacy Policy or AreumSec’s data practices, contact us at:
- **Email**: [Insert your support email, e.g., support@areumsec.com]
- **Website**: [Insert your website, if applicable, e.g., https://areumsec.com]

We are committed to addressing your concerns promptly.

---

**Note**: This Privacy Policy applies only to the AreumSec extension. Other websites or services you visit may have their own privacy policies.