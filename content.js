// Enhanced content script with better warning display and removal
let currentWarning = null;

function checkAndDisplayWarning() {
  chrome.storage.local.get(['urlSafetyResults'], (data) => {
    const results = data.urlSafetyResults || {};
    const isMalicious = Object.values(results).some(r => r.verdict === 'Malicious');
    
    // Remove existing warning if present
    if (currentWarning) {
      currentWarning.remove();
      currentWarning = null;
    }
    
    if (isMalicious) {
      currentWarning = document.createElement('div');
      currentWarning.className = 'cyberpunk-warning';
      currentWarning.textContent = 'AreumSec Alert: This URL may be unsafe! Check the extension for details.';
      document.body.prepend(currentWarning);

      currentWarning.style.cssText = `
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
        width: 100%;
        z-index: 9999;
        box-shadow: 0 4px 20px rgba(255, 0, 77, 0.3);
      `;
    }
  });
}

// Initial check
checkAndDisplayWarning();

// Listen for updates from background
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'safetyUpdate') {
    checkAndDisplayWarning();
  }
});