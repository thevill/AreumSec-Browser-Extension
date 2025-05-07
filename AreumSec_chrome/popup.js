document.addEventListener('DOMContentLoaded', () => {
    const loading = document.getElementById('loading');
    const resultsDiv = document.getElementById('results');
    const urlDisplay = document.getElementById('current-url');
    const apiHint = document.getElementById('apiHint');
    const optionsLink = document.querySelector('[data-options-link]');
    let storageListener = null;
    let currentUrl = null;

    if (!loading || !resultsDiv || !urlDisplay || !apiHint || !optionsLink) {
        console.error('Required DOM elements missing');
        showError('Required DOM elements missing');
        return;
    }

    // Check for API keys and toggle hint visibility
    chrome.storage.sync.get(['vtApiKey', 'gsbApiKey'], (data) => {
        const hasVtApiKey = data.vtApiKey && data.vtApiKey.trim() !== '';
        const hasGsbApiKey = data.gsbApiKey && data.gsbApiKey.trim() !== '';
        requestAnimationFrame(() => {
            apiHint.style.display = (!hasVtApiKey && !hasGsbApiKey) ? 'block' : 'none';
        });
    });

    // Add click event listener to open options page
    optionsLink.addEventListener('click', (e) => {
        e.preventDefault();
        chrome.runtime.openOptionsPage();
    });

    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (chrome.runtime.lastError || !tabs[0]?.url) {
            console.error('Error accessing current tab:', chrome.runtime.lastError);
            showError('Unable to access current tab');
            return;
        }

        currentUrl = normalizeUrl(tabs[0].url);
        urlDisplay.textContent = currentUrl;
        checkResults(currentUrl);
    });

    // Check results with URL validation
    function checkResults(url) {
        loading.style.display = 'flex';
        resultsDiv.style.display = 'none';

        storageListener = chrome.storage.local.onChanged.addListener((changes) => {
            if (changes.urlSafetyResults) {
                const results = changes.urlSafetyResults.newValue || {};
                const cacheKey = `cache_${url}`;
                chrome.storage.local.get([cacheKey, 'currentUrl'], (data) => {
                    if (!data.currentUrl || data.currentUrl !== url) {
                        console.warn('Results URL mismatch:', data.currentUrl, 'vs', url);
                        triggerManualCheck(url);
                        return;
                    }
                    if (data[cacheKey] && isEqualResults(data[cacheKey], results)) {
                        displayResults(results, url);
                    } else {
                        triggerManualCheck(url);
                    }
                });
            }
        });

        // Initial check
        chrome.runtime.sendMessage({ action: "getResults", url }, (response) => {
            if (chrome.runtime.lastError) {
                console.error('Message error:', chrome.runtime.lastError);
                triggerManualCheck(url);
                return;
            }
            chrome.storage.local.get(['currentUrl'], (data) => {
                if (!data.currentUrl || data.currentUrl !== url) {
                    console.warn('Initial results URL mismatch:', data.currentUrl, 'vs', url);
                    triggerManualCheck(url);
                    return;
                }
                if (response && Object.keys(response).length > 0 && response.urlhaus) {
                    const cacheKey = `cache_${url}`;
                    chrome.storage.local.get([cacheKey], (data) => {
                        if (data[cacheKey] && isEqualResults(data[cacheKey], response)) {
                            displayResults(response, url);
                        } else {
                            triggerManualCheck(url);
                        }
                    });
                } else {
                    triggerManualCheck(url);
                }
            });
        });
    }

    function isEqualResults(a, b) {
        return JSON.stringify(a, Object.keys(a).sort()) === JSON.stringify(b, Object.keys(b).sort());
    }

    function triggerManualCheck(url, attempts = 3) {
        console.log('Triggering manual check for:', url, 'attempts:', attempts);
        chrome.runtime.sendMessage({ action: "checkUrl", url }, (response) => {
            if (chrome.runtime.lastError || response.status !== 'success') {
                console.error('Manual check error:', chrome.runtime.lastError || response.message);
                if (attempts > 0) {
                    setTimeout(() => triggerManualCheck(url, attempts - 1), 1000);
                } else {
                    displayFallbackResult(url, response.message || 'Failed to scan URL. Please try again.');
                }
                return;
            }
            // Results will be handled by storage listener
        });
    }

    function displayFallbackResult(url, errorMessage) {
        loading.style.display = 'none';
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = `
            <div class="result error">
                <span class="service-name">AreumSec</span>: 
                <span class="verdict error">Error</span>
                <p class="error-message">${errorMessage}</p>
                <div class="retry-button-container">
                    <button class="cyberpunk-button" id="retry-button">Retry Scan</button>
                </div>
            </div>
        `;
        const retryButton = document.getElementById('retry-button');
        if (retryButton) {
            retryButton.addEventListener('click', () => {
                loading.style.display = 'flex';
                resultsDiv.style.display = 'none';
                triggerManualCheck(url, 3);
            });
        }
    }

    function displayResults(results, url) {
        chrome.storage.local.get(['currentUrl'], (data) => {
            if (!data.currentUrl || data.currentUrl !== url) {
                console.warn('Discarding stale results for:', url);
                triggerManualCheck(url);
                return;
            }
            requestAnimationFrame(() => {
                loading.style.display = 'none';
                resultsDiv.style.display = 'block';
                resultsDiv.innerHTML = '';

                const { malicious, safe, error } = categorizeResults(results);

                if (malicious.length > 0) {
                    resultsDiv.appendChild(createHeader('Warning: Potential Threats Detected', 'warning-header'));
                    malicious.forEach(result => resultsDiv.appendChild(createResultElement(result, 'malicious')));
                }
                if (safe.length > 0) {
                    resultsDiv.appendChild(createHeader('Safe Results', 'safe-header'));
                    safe.forEach(result => resultsDiv.appendChild(createResultElement(result, 'safe')));
                }
                if (error.length > 0) {
                    resultsDiv.appendChild(createHeader('Service Errors', 'error-header'));
                    error.forEach(result => resultsDiv.appendChild(createResultElement(result, 'error')));
                }
            });
        });
    }

    function categorizeResults(results) {
        const malicious = [], safe = [], error = [];
        for (const [service, result] of Object.entries(results)) {
            const item = { service, verdict: result.verdict || 'Unknown', details: result.details, error: result.error, source: result.source || service };
            if (result.verdict === 'Malicious') malicious.push(item);
            else if (result.verdict === 'Safe') safe.push(item);
            else error.push(item);
        }
        return { malicious, safe, error };
    }

    function createHeader(text, className) {
        const header = document.createElement('h3');
        header.className = className;
        header.textContent = text;
        return header;
    }

    function createResultElement(result, type) {
        const div = document.createElement('div');
        div.className = `result ${type}`;
        div.innerHTML = `
            <span class="service-name">${result.source}</span>: 
            <span class="verdict ${type}">${result.verdict}</span>
            ${result.error ? `<p class="error-message">${result.error.replace('Rate limit exceeded', 'URLhaus rate limit reached (5/day)')}</p>` : ''}
            ${result.details ? `<p class="details">${typeof result.details === 'string' ? result.details : JSON.stringify(result.details, null, 2)}</p>` : ''}
        `;
        return div;
    }

    function showError(message) {
        loading.style.display = 'none';
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = `<div class="error-message">${message}</div>`;
    }

    function normalizeUrl(url) {
        try {
            const urlObj = new URL(url);
            let normalized = `${urlObj.protocol}//${urlObj.hostname}${urlObj.pathname}`;
            if (url.endsWith('/') && !normalized.endsWith('/')) normalized += '/';
            if (urlObj.port) normalized = normalized.replace('//', `//${urlObj.hostname}:${urlObj.port}`);
            return normalized.toLowerCase();
        } catch {
            return url;
        }
    }

    // Cleanup on popup close
    window.addEventListener('unload', () => {
        if (storageListener) {
            chrome.storage.local.onChanged.removeListener(storageListener);
        }
    });
});