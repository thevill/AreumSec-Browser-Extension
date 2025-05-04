document.addEventListener('DOMContentLoaded', () => {
    const loading = document.getElementById('loading');
    const resultsDiv = document.getElementById('results');
    const urlDisplay = document.getElementById('current-url');
    
    if (!loading || !resultsDiv || !urlDisplay) {
        console.error('Required elements not found');
        showError('Required elements not found');
        return;
    }

    chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
        if (chrome.runtime.lastError) {
            console.error('Error accessing current tab:', chrome.runtime.lastError);
            showError('Error accessing current tab');
            return;
        }

        const currentTab = tabs[0];
        if (!currentTab || !currentTab.url) {
            console.error('No active tab with URL found');
            showError('No active tab with URL found');
            return;
        }
        
        try {
            console.log('Current URL:', currentTab.url);
            urlDisplay.textContent = currentTab.url;
            checkResults(currentTab.url);
        } catch (e) {
            console.error('Error setting URL:', e);
            showError('Error processing URL');
        }
    });

    function checkResults(url, attempts = 30, delay = 500) {
        console.log('Checking results for:', url, 'attempts left:', attempts);
        chrome.runtime.sendMessage({action: "getResults"}, (response) => {
            if (chrome.runtime.lastError) {
                console.error('Message error:', chrome.runtime.lastError);
                pollStorageForResults(url, attempts, delay);
                return;
            }

            console.log('Message response:', response);
            if (response && Object.keys(response).length > 0 && response.urlhaus) {
                const cacheKey = `cache_${url}`;
                chrome.storage.local.get([cacheKey], (data) => {
                    if (data[cacheKey] && JSON.stringify(data[cacheKey]) === JSON.stringify(response)) {
                        console.log('Results match current URL:', url);
                        displayResults(response);
                    } else {
                        console.warn('Results mismatch for:', url, 'triggering manual check');
                        triggerManualCheck(url, attempts);
                    }
                });
            } else {
                console.log('Empty or invalid results, polling storage');
                pollStorageForResults(url, attempts, delay);
            }
        });
    }

    function pollStorageForResults(url, attempts, delay) {
        console.log('Polling storage for:', url, 'attempts left:', attempts);
        chrome.storage.local.get(['urlSafetyResults'], (data) => {
            if (chrome.runtime.lastError) {
                console.error('Storage error:', chrome.runtime.lastError);
                if (attempts > 0) {
                    setTimeout(() => pollStorageForResults(url, attempts - 1, delay), delay);
                } else {
                    triggerManualCheck(url, attempts);
                }
                return;
            }

            const results = data.urlSafetyResults || {};
            console.log('Storage results:', results);
            
            if (Object.keys(results).length > 0 && results.urlhaus) {
                const cacheKey = `cache_${url}`;
                chrome.storage.local.get([cacheKey], (data) => {
                    if (data[cacheKey] && JSON.stringify(data[cacheKey]) === JSON.stringify(results)) {
                        console.log('Storage results match current URL:', url);
                        displayResults(results);
                    } else {
                        console.warn('Storage results mismatch for:', url, 'triggering manual check');
                        triggerManualCheck(url, attempts);
                    }
                });
            } else if (attempts > 0) {
                setTimeout(() => pollStorageForResults(url, attempts - 1, delay), delay);
            } else {
                triggerManualCheck(url, attempts);
            }
        });
    }

    function triggerManualCheck(url, attempts = 30) {
        console.log('Triggering manual check for:', url, 'attempts:', attempts);
        chrome.runtime.sendMessage({action: "checkUrl", url}, (response) => {
            if (chrome.runtime.lastError) {
                console.error('Manual check error:', chrome.runtime.lastError);
                if (attempts > 0) {
                    setTimeout(() => triggerManualCheck(url, attempts - 1), 500);
                } else {
                    displayFallbackResult(url, 'Failed to initiate scan');
                }
                return;
            }
            console.log('Manual check response:', response);
            if (response.status === 'success') {
                checkResults(url, 15, 500);
            } else if (attempts > 0) {
                setTimeout(() => triggerManualCheck(url, attempts - 1), 500);
            } else {
                displayFallbackResult(url, response.message || 'No scan results available');
            }
        });
    }

    function displayFallbackResult(url, errorMessage) {
        console.log('No results after polling, displaying fallback for:', url);
        loading.style.display = 'none';
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = '';
        
        const resultDiv = document.createElement('div');
        resultDiv.className = 'result error';
        resultDiv.innerHTML = `
            <span class="service-name">AreumSec</span>: 
            <span class="verdict error">Error</span>
            <p class="error-message">${errorMessage} for ${url}</p>
        `;
        resultsDiv.appendChild(resultDiv);
    }

    function displayResults(results) {
        try {
            console.log('Displaying results:', results);
            loading.style.display = 'none';
            resultsDiv.style.display = 'block';
            resultsDiv.innerHTML = '';
            
            const maliciousResults = [];
            const safeResults = [];
            const errorResults = [];
            
            for (const [service, result] of Object.entries(results)) {
                const resultItem = {
                    service,
                    verdict: result.verdict || 'Unknown',
                    details: result.details,
                    error: result.error,
                    source: result.source || service
                };
                
                if (result.verdict === 'Malicious') {
                    maliciousResults.push(resultItem);
                } else if (result.verdict === 'Safe') {
                    safeResults.push(resultItem);
                } else {
                    errorResults.push(resultItem);
                }
            }
            
            if (maliciousResults.length > 0) {
                const warningHeader = document.createElement('h3');
                warningHeader.className = 'warning-header';
                warningHeader.textContent = 'Warning: Potential Threats Detected';
                resultsDiv.appendChild(warningHeader);
                
                maliciousResults.forEach(result => {
                    resultsDiv.appendChild(createResultElement(result, 'malicious'));
                });
            }
            
            if (safeResults.length > 0) {
                const safeHeader = document.createElement('h3');
                safeHeader.className = 'safe-header';
                safeHeader.textContent = 'Safe Results';
                resultsDiv.appendChild(safeHeader);
                
                safeResults.forEach(result => {
                    resultsDiv.appendChild(createResultElement(result, 'safe'));
                });
            }
            
            if (errorResults.length > 0) {
                const errorHeader = document.createElement('h3');
                errorHeader.className = 'error-header';
                warningHeader.textContent = 'Warning: Service Errors';
                resultsDiv.appendChild(errorHeader);
                
                errorResults.forEach(result => {
                    resultsDiv.appendChild(createResultElement(result, 'error'));
                });
            }
        } catch (e) {
            console.error('Error displaying results:', e);
            showError('Error displaying scan results');
        }
    }
    
    function createResultElement(result, type) {
        const resultDiv = document.createElement('div');
        resultDiv.className = `result ${type}`;
        
        const serviceSpan = document.createElement('span');
        serviceSpan.className = 'service-name';
        serviceSpan.textContent = result.source;
        
        const verdictSpan = document.createElement('span');
        verdictSpan.className = `verdict ${type}`;
        verdictSpan.textContent = result.verdict;
        
        resultDiv.appendChild(serviceSpan);
        resultDiv.appendChild(document.createTextNode(': '));
        resultDiv.appendChild(verdictSpan);
        
        if (result.error) {
            const errorP = document.createElement('p');
            errorP.className = 'error-message';
            errorP.textContent = result.error.replace('Rate limit exceeded', 'URLhaus rate limit reached (5/day)');
            resultDiv.appendChild(errorP);
        }
        
        if (result.details) {
            const detailsP = document.createElement('p');
            detailsP.className = 'details';
            detailsP.textContent = typeof result.details === 'string' ? 
                result.details : 
                JSON.stringify(result.details, null, 2);
            resultDiv.appendChild(detailsP);
        }
        
        return resultDiv;
    }
    
    function showError(message) {
        try {
            console.error('Showing error:', message);
            loading.style.display = 'none';
            resultsDiv.innerHTML = `
                <div class="error-message">
                    ${message}
                </div>
            `;
            resultsDiv.style.display = 'block';
        } catch (e) {
            console.error('Error showing error:', e);
        }
    }
});