document.addEventListener('DOMContentLoaded', () => {
    const saveButton = document.getElementById('save');
    const statusDiv = document.getElementById('status');
    const vtApiKeyInput = document.getElementById('vtApiKey');
    const gsbApiKeyInput = document.getElementById('gsbApiKey');
  
    if (!saveButton || !statusDiv || !vtApiKeyInput || !gsbApiKeyInput) {
      console.error('Required elements not found');
      statusDiv.textContent = 'Error: UI elements missing';
      statusDiv.className = 'status-message error show';
      return;
    }
  
    // Load saved keys
    chrome.storage.sync.get(['vtApiKey', 'gsbApiKey'], (data) => {
      if (chrome.runtime.lastError) {
        console.error('Error loading keys:', chrome.runtime.lastError);
        statusDiv.textContent = 'Error loading configuration';
        statusDiv.className = 'status-message error show';
        return;
      }
      vtApiKeyInput.value = data.vtApiKey || '';
      gsbApiKeyInput.value = data.gsbApiKey || '';
      console.log('Loaded keys - vtApiKey:', !!data.vtApiKey, 'gsbApiKey:', !!data.gsbApiKey);
    });
  
    // Save keys on button click
    saveButton.addEventListener('click', () => {
      const vtApiKey = vtApiKeyInput.value.trim();
      const gsbApiKey = gsbApiKeyInput.value.trim();
  
      // Validate VirusTotal API key format
      if (vtApiKey && !/^[a-z0-9]{64}$/.test(vtApiKey)) {
        console.error('Invalid VirusTotal API key format');
        statusDiv.textContent = 'Error: Invalid VirusTotal API key format (must be 64 alphanumeric characters)';
        statusDiv.className = 'status-message error show';
        setTimeout(() => {
          statusDiv.textContent = '';
          statusDiv.className = 'status-message';
        }, 3000);
        return;
      }
  
      // Validate Google Safe Browsing API key format
      if (gsbApiKey && !/^[a-zA-Z0-9_-]{20,}$/.test(gsbApiKey)) {
        console.error('Invalid GSB API key format');
        statusDiv.textContent = 'Error: Invalid Google Safe Browsing API key format';
        statusDiv.className = 'status-message error show';
        setTimeout(() => {
          statusDiv.textContent = '';
          statusDiv.className = 'status-message';
        }, 3000);
        return;
      }
  
      chrome.storage.sync.set({ vtApiKey, gsbApiKey }, () => {
        if (chrome.runtime.lastError) {
          console.error('Error saving configuration:', chrome.runtime.lastError);
          statusDiv.textContent = 'Error saving configuration';
          statusDiv.className = 'status-message error show';
        } else {
          console.log('Configuration saved successfully - vtApiKey:', !!vtApiKey, 'gsbApiKey:', gsbApiKey ? '****' + gsbApiKey.slice(-4) : 'None');
          statusDiv.textContent = 'Configuration saved successfully';
          statusDiv.className = 'status-message success show';
        }
        // Clear message after 3 seconds
        setTimeout(() => {
          statusDiv.textContent = '';
          statusDiv.className = 'status-message';
        }, 3000);
      });
    });
  });