let currentWarning = null;

function checkAndDisplayWarning() {
    console.log('Checking URL safety results...');
    chrome.storage.local.get(['urlSafetyResults'], (data) => {
        console.log('Storage data:', data);
        const results = data.urlSafetyResults || {};
        const isMalicious = Object.values(results).some(r => r.verdict === 'Malicious');
        console.log('Is malicious:', isMalicious);

        if (currentWarning) {
            console.log('Removing existing warning');
            currentWarning.remove();
            currentWarning = null;
        }

        if (isMalicious) {
            console.log('Creating warning for malicious URL');
            const shadowHost = document.createElement('div');
            const shadowRoot = shadowHost.attachShadow({ mode: 'open' });
            currentWarning = shadowHost;

            const warning = document.createElement('div');
            warning.className = 'cyberpunk-warning';
            warning.textContent = 'AreumSec Alert: This URL may be unsafe! Check the extension for details.';
            warning.setAttribute('role', 'alert');

            //const warningLine = document.createElement('div');
            //warningLine.className = 'warning-line';
            //warningLine.textContent = 'URL is detected as malicious';

            const dismissButton = document.createElement('button');
            dismissButton.textContent = 'Dismiss';
            dismissButton.className = 'dismiss-button';

            const style = document.createElement('style');
            style.textContent = `
                .cyberpunk-warning {
                    background: linear-gradient(90deg, #1a1a1a, #2a2a2a);
                    color: #ff004d;
                    text-shadow: 0 0 10px #ff004d;
                    padding: 15px;
                    font-family: 'Orbitron', sans-serif;
                    font-size: 16px;
                    text-align: center;
                    border-bottom: 2px solid #00ffcc;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100vw;
                    box-sizing: border-box;
                    z-index: 9999;
                    box-shadow: 0 4px 20px rgba(255, 0, 77, 0.3);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }
                .warning-line {
                    background: #1a1a1a;
                    color: #ff004d;
                    font-weight: bold;
                    font-family: 'Orbitron', sans-serif;
                    font-size: 14px;
                    text-align: center;
                    padding: 10px;
                    border-top: 1px solid #00ffcc;
                    position: fixed;
                    top: 52px;
                    left: 0;
                    width: 100vw;
                    box-sizing: border-box;
                    z-index: 9998;
                }
                .dismiss-button {
                    margin-left: 10px;
                    padding: 5px 10px;
                    background: #ff004d;
                    color: #fff;
                    border: none;
                    border-radius: 3px;
                    cursor: pointer;
                    font-family: 'Orbitron', sans-serif;
                    -webkit-tap-highlight-color: transparent;
                }
                .dismiss-button:hover, .dismiss-button:active {
                    background: #e60045;
                }
            `;

            warning.appendChild(dismissButton);
            shadowRoot.appendChild(style);
            shadowRoot.appendChild(warning);
            //shadowRoot.appendChild(warningLine);
            document.body.prepend(shadowHost);

            dismissButton.onclick = () => {
                console.log('Dismiss button clicked');
                shadowHost.remove();
            };
        } else {
            console.log('No malicious URL detected');
        }
    });
}

// Throttle updates
let lastCheck = 0;
const throttleCheck = () => {
    const now = Date.now();
    if (now - lastCheck > 1000) {
        lastCheck = now;
        checkAndDisplayWarning();
    }
};

// Initial check
throttleCheck();

// Listen for updates
chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'safetyUpdate') {
        console.log('Received safety update message');
        throttleCheck();
    }
});