let cache = {
    urls: new Set(),
    lastPull: 0,
    pullCount: 0,
    lastPullDay: 0,
    maxPullsPerDay: 5,
    pullInterval: 86400 * 1000 / 5 // ~4.8 hours (17,280 seconds)
};

chrome.storage.local.get(['urlhausCache'], (data) => {
    if (!chrome.runtime.lastError && data.urlhausCache) {
        cache.urls = new Set(data.urlhausCache.urls || []);
        cache.lastPull = data.urlhausCache.lastPull || 0;
        cache.pullCount = data.urlhausCache.pullCount || 0;
        cache.lastPullDay = data.urlhausCache.lastPullDay || 0;
        console.log('Loaded cache:', cache.urls.size, 'URLs, pullCount:', cache.pullCount, 'lastPullDay:', new Date(cache.lastPullDay));
    } else {
        console.log('No cached URLhaus data found');
    }
});

function saveCache() {
    chrome.storage.local.set({
        urlhausCache: {
            urls: Array.from(cache.urls),
            lastPull: cache.lastPull,
            pullCount: cache.pullCount,
            lastPullDay: cache.lastPullDay
        }
    }, () => {
        if (chrome.runtime.lastError) {
            console.error('Error saving cache:', chrome.runtime.lastError);
        } else {
            console.log('Cache saved:', cache.urls.size, 'URLs, pullCount:', cache.pullCount);
        }
    });
}

function canPull() {
    const now = Date.now();
    const currentDay = Math.floor(now / (24 * 60 * 60 * 1000));
    
    if (currentDay > cache.lastPullDay) {
        cache.pullCount = 0;
        cache.lastPullDay = currentDay;
        console.log('New day, reset pull count to 0');
    }
    
    const can = cache.pullCount < cache.maxPullsPerDay && 
                (now - cache.lastPull >= cache.pullInterval || cache.urls.size === 0);
    console.log('Can pull URLhaus:', can, 'pullCount:', cache.pullCount, 'urls:', cache.urls.size);
    return can;
}

const CACHE_DURATION = 60 * 60 * 1000; // 1 hour
const RATE_LIMIT = {
    virustotal: { max: 4, window: 60 * 1000 },
    googleSafeBrowsing: { max: 10000, window: 24 * 60 * 60 * 1000 }
};
let requestCounts = { virustotal: 0, googleSafeBrowsing: 0 };

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getResults") {
        console.log('Received getResults request');
        chrome.storage.local.get(['urlSafetyResults'], (data) => {
            if (chrome.runtime.lastError) {
                console.error('Storage error in getResults:', chrome.runtime.lastError);
                sendResponse({});
            } else {
                console.log('Sending results:', data.urlSafetyResults || {});
                sendResponse(data.urlSafetyResults || {});
            }
        });
        return true;
    }
    if (request.action === "checkUrl") {
        console.log('Received checkUrl request for:', request.url);
        chrome.storage.sync.get(['vtApiKey', 'gsbApiKey'], (data) => {
            if (chrome.runtime.lastError) {
                console.error('Error accessing storage:', chrome.runtime.lastError);
                saveErrorResult(request.url, 'Storage access failed');
                sendResponse({ status: 'error', message: 'Storage access failed' });
            } else {
                console.log('Storage retrieved - vtApiKey:', !!data.vtApiKey, 'gsbApiKey:', !!data.gsbApiKey);
                checkUrlSafety(request.url, data.vtApiKey, data.gsbApiKey).then(() => {
                    sendResponse({ status: 'success' });
                }).catch((e) => {
                    console.error('Check URL failed:', e);
                    sendResponse({ status: 'error', message: e.message });
                });
            }
        });
        return true;
    }
});

chrome.webNavigation.onCommitted.addListener((details) => {
    console.log('Navigation committed:', details);
    if (details.frameId === 0) {
        console.log('Main frame committed:', details.url);
        chrome.storage.local.remove(['urlSafetyResults'], () => {
            if (chrome.runtime.lastError) {
                console.error('Error clearing urlSafetyResults:', chrome.runtime.lastError);
            } else {
                console.log('Cleared urlSafetyResults for:', details.url);
            }
        });
        chrome.storage.sync.get(['vtApiKey', 'gsbApiKey'], (data) => {
            if (chrome.runtime.lastError) {
                console.error('Error accessing storage:', chrome.runtime.lastError);
                saveErrorResult(details.url, 'Storage access failed');
                return;
            }
            console.log('Storage retrieved for navigation - vtApiKey:', !!data.vtApiKey, 'gsbApiKey:', !!data.gsbApiKey);
            checkUrlSafety(details.url, data.vtApiKey, data.gsbApiKey);
        });
    }
}, { url: [{ urlMatches: 'http://*/*' }, { urlMatches: 'https://*/*' }] });

chrome.webNavigation.onCompleted.addListener((details) => {
    console.log('Navigation completed:', details);
    if (details.frameId === 0) {
        console.log('Main frame completed:', details.url);
        chrome.storage.sync.get(['vtApiKey', 'gsbApiKey'], (data) => {
            if (chrome.runtime.lastError) {
                console.error('Error accessing storage:', chrome.runtime.lastError);
                saveErrorResult(details.url, 'Storage access failed');
                return;
            }
            console.log('Storage retrieved for navigation complete - vtApiKey:', !!data.vtApiKey, 'gsbApiKey:', !!data.gsbApiKey);
            checkUrlSafety(details.url, data.vtApiKey, data.gsbApiKey);
        });
    }
}, { url: [{ urlMatches: 'http://*/*' }, { urlMatches: 'https://*/*' }] });

async function checkUrlSafety(url, vtApiKey, gsbApiKey) {
    console.log('Checking URL safety:', url);
    const cacheKey = `cache_${url}`;
    try {
        if (!isValidUrl(url)) {
            console.warn('Invalid URL, skipping:', url);
            await saveErrorResult(url, 'Invalid URL');
            return;
        }

        const cached = await getCachedResult(cacheKey);
        if (cached) {
            console.log('Using cached result:', cached);
            await saveResults(cached, cacheKey, url);
            return;
        }

        const results = {};
        const now = Date.now();

        resetRateLimits(now);

        try {
            results.urlhaus = await checkUrlhaus(url);
            results.urlhaus.source = 'URLhaus';
        } catch (e) {
            console.error('URLhaus check failed:', e);
            results.urlhaus = { 
                verdict: 'Error', 
                error: `URLhaus: ${e.message}`, 
                timestamp: now,
                source: 'URLhaus'
            };
        }

        await checkOtherServices(url, vtApiKey, gsbApiKey, results, now);
        await saveAndNotify(results, cacheKey, url, now);
    } catch (e) {
        console.error('URL safety check failed:', e);
        await saveErrorResult(url, `Safety check failed: ${e.message}`);
    }
}

async function saveErrorResult(url, errorMessage) {
    const cacheKey = `cache_${url}`;
    const results = {
        default: { 
            verdict: 'Error', 
            error: errorMessage, 
            timestamp: Date.now(),
            source: 'AreumSec'
        }
    };
    await saveResults(results, cacheKey, url);
}

function resetRateLimits(now) {
    if (now - (requestCounts.virustotalLastReset || 0) > RATE_LIMIT.virustotal.window) {
        requestCounts.virustotal = 0;
        requestCounts.virustotalLastReset = now;
    }
    if (now - (requestCounts.googleSafeBrowsingLastReset || 0) > RATE_LIMIT.googleSafeBrowsing.window) {
        requestCounts.googleSafeBrowsing = 0;
        requestCounts.googleSafeBrowsingLastReset = now;
        console.log('Reset GSB rate limit, request count:', requestCounts.googleSafeBrowsing);
    }
}

async function checkOtherServices(url, vtApiKey, gsbApiKey, results, now) {
    const checks = [];
    console.log('Checking other services for:', url, 'vtApiKey:', !!vtApiKey, 'gsbApiKey:', gsbApiKey ? '****' + gsbApiKey.slice(-4) : 'None');
    
    if (vtApiKey && requestCounts.virustotal < RATE_LIMIT.virustotal.max) {
        checks.push(checkVirusTotal(url, vtApiKey).then(res => {
            results.virustotal = res;
            requestCounts.virustotal++;
        }).catch(e => {
            results.virustotal = { 
                verdict: 'Error', 
                error: `VirusTotal: ${e.message}`, 
                timestamp: now,
                source: 'VirusTotal'
            };
        }));
    } else if (!vtApiKey) {
        console.log('No VirusTotal API key provided, skipping VT check');
    } else {
        console.log('VirusTotal rate limit reached, skipping check. Request count:', requestCounts.virustotal);
    }

    console.log('GSB rate limit check - count:', requestCounts.googleSafeBrowsing, 'max:', RATE_LIMIT.googleSafeBrowsing.max);
    if (gsbApiKey && requestCounts.googleSafeBrowsing < RATE_LIMIT.googleSafeBrowsing.max && url.startsWith('http')) {
        console.log('Initiating GSB check for:', url);
        checks.push(checkGoogleSafeBrowsing(url, gsbApiKey).then(res => {
            results.googleSafeBrowsing = res;
            requestCounts.googleSafeBrowsing++;
            console.log('GSB check completed, result:', res);
        }).catch(e => {
            console.error('GSB check failed:', e);
            results.googleSafeBrowsing = { 
                verdict: 'Error', 
                error: `Google Safe Browsing: ${e.message}`, 
                timestamp: now,
                source: 'Google Safe Browsing'
            };
        }));
    } else {
        const reason = !gsbApiKey ? 'No API key provided' : 
                      !url.startsWith('http') ? 'Non-HTTP URL' : 
                      'Rate limit reached';
        console.log(`Skipping GSB check for ${url}: ${reason}`);
        results.googleSafeBrowsing = { 
            verdict: 'Unknown', 
            error: `Google Safe Browsing: ${reason}`, 
            timestamp: now,
            source: 'Google Safe Browsing'
        };
    }

    await Promise.all(checks);
}

async function saveAndNotify(results, cacheKey, url, timestamp) {
    const resultWithTimestamp = Object.fromEntries(
        Object.entries(results).map(([k, v]) => [k, { ...v, timestamp }])
    );
    
    await saveResults(resultWithTimestamp, cacheKey, url);
    notifyIfMalicious(resultWithTimestamp);
}

async function saveResults(results, cacheKey, url) {
    return new Promise((resolve) => {
        console.log('Saving results for:', cacheKey, results);
        chrome.storage.local.get([cacheKey, 'urlSafetyResults'], (data) => {
            const currentResults = data.urlSafetyResults || {};
            if (JSON.stringify(currentResults) === JSON.stringify(results) && data[cacheKey]) {
                console.log('Results already up-to-date for:', cacheKey);
                resolve();
                return;
            }
            chrome.storage.local.get(null, (items) => {
                const keysToRemove = Object.keys(items).filter(k => k.startsWith('cache_') && k !== cacheKey);
                if (keysToRemove.length > 0) {
                    chrome.storage.local.remove(keysToRemove, () => {
                        if (chrome.runtime.lastError) {
                            console.error('Error clearing stale cache keys:', chrome.runtime.lastError);
                        } else {
                            console.log('Cleared stale cache keys:', keysToRemove);
                        }
                    });
                }
                chrome.storage.local.set({
                    [cacheKey]: results,
                    urlSafetyResults: results
                }, () => {
                    if (chrome.runtime.lastError) {
                        console.error('Error saving results:', chrome.runtime.lastError);
                    } else {
                        console.log('Results saved for:', cacheKey);
                    }
                    resolve();
                });
            });
        });
    });
}

function notifyIfMalicious(results) {
    if (Object.values(results).some(r => r.verdict === 'Malicious')) {
        console.log('Notifying malicious URL');
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon48.png',
            title: 'AreumSec Alert',
            message: 'This URL may be unsafe! Check the AreumSec popup for details.',
            priority: 2
        });
    }
}

async function getCachedResult(cacheKey) {
    return new Promise((resolve) => {
        chrome.storage.local.get([cacheKey], (result) => {
            if (chrome.runtime.lastError) {
                console.error('Error getting cached result:', chrome.runtime.lastError);
                resolve(null);
            } else if (result[cacheKey] && 
                Date.now() - (result[cacheKey].urlhaus?.timestamp || 0) < CACHE_DURATION) {
                console.log('Cache hit for:', cacheKey);
                resolve(result[cacheKey]);
            } else {
                console.log('Cache miss or expired for:', cacheKey);
                resolve(null);
            }
        });
    });
}

function normalizeUrl(url) {
    try {
        const urlObj = new URL(url);
        let normalized = `${urlObj.protocol}//${urlObj.hostname}${urlObj.pathname}`;
        if (url.endsWith('/') && !normalized.endsWith('/')) {
            normalized += '/';
        }
        if (urlObj.port) {
            normalized = normalized.replace('//', `//${urlObj.hostname}:${urlObj.port}`);
        }
        return normalized;
    } catch {
        console.warn('Invalid URL:', url);
        return url;
    }
}

function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

async function checkUrlhaus(url) {
    const normalizedUrl = normalizeUrl(url);
    console.log('Checking URLhaus for:', normalizedUrl);
    const lowerUrl = normalizedUrl.toLowerCase();
    let verdict = 'Safe';
    let details = 'Not found in URLhaus data';

    if (cache.urls.size > 0 && Array.from(cache.urls).some(u => {
        const uLower = u.toLowerCase();
        return uLower === lowerUrl || uLower + '/' === lowerUrl || uLower === lowerUrl + '/';
    })) {
        console.log('URL found in cache:', normalizedUrl);
        return { 
            verdict: 'Malicious', 
            details: 'Found in URLhaus cache',
            source: 'URLhaus'
        };
    }

    if (canPull()) {
        try {
            console.log('Fetching URLhaus text list...');
            const textResponse = await fetch('https://urlhaus.abuse.ch/downloads/text/', { 
                signal: AbortSignal.timeout(15000),
                headers: { 'Accept': 'text/plain' }
            });
            if (!textResponse.ok) throw new Error(`HTTP ${textResponse.status}: ${textResponse.statusText}`);
            const text = await textResponse.text();
            console.log('URLhaus text list fetched, size:', text.length);
            const textLines = text.split('\n').filter(line => line.trim() && !line.startsWith('#') && isValidUrl(line));
            console.log('URLhaus text list parsed, entries:', textLines.length);
            
            for (const line of textLines) {
                const normalizedLine = normalizeUrl(line);
                cache.urls.add(normalizedLine);
                const lineLower = normalizedLine.toLowerCase();
                if (lineLower === lowerUrl || lineLower + '/' === lowerUrl || lineLower === lowerUrl + '/') {
                    console.log('Matched URL in plain-text list:', normalizedLine);
                    verdict = 'Malicious';
                    details = 'Found in URLhaus plain-text list';
                    break;
                }
            }

            if (verdict !== 'Malicious') {
                try {
                    console.log('Fetching URLhaus ClamAV signatures...');
                    const ndbResponse = await fetch('https://urlhaus.abuse.ch/downloads/urlhaus.ndb', { 
                        signal: AbortSignal.timeout(15000),
                        headers: { 'Accept': 'text/plain' }
                    });
                    if (!ndbResponse.ok) throw new Error(`HTTP ${ndbResponse.status}: ${textResponse.statusText}`);
                    const ndbText = await ndbResponse.text();
                    console.log('URLhaus ClamAV signatures fetched, size:', ndbText.length);
                    const ndbLines = ndbText.split('\n').filter(line => line.trim() && !line.startsWith('#'));
                    console.log('URLhaus ClamAV signatures parsed, entries:', ndbLines.length);
                    
                    for (const line of ndbLines) {
                        const parts = line.split(':');
                        if (parts.length >= 4) {
                            const hexSignature = parts[3].trim();
                            try {
                                const decodedUrl = new TextDecoder('utf-8').decode(
                                    new Uint8Array(
                                        hexSignature.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []
                                    )
                                ).trim();
                                if (isValidUrl(decodedUrl)) {
                                    const normalizedDecodedUrl = normalizeUrl(decodedUrl);
                                    cache.urls.add(normalizedDecodedUrl);
                                    const decodedLower = normalizedDecodedUrl.toLowerCase();
                                    if (decodedLower === lowerUrl || decodedLower + '/' === lowerUrl || decodedLower === lowerUrl + '/') {
                                        console.log('Matched URL in ClamAV signatures:', normalizedDecodedUrl);
                                        verdict = 'Malicious';
                                        details = 'Matches ClamAV signature';
                                        break;
                                    }
                                }
                            } catch (e) {
                                console.error('ClamAV decode error:', e);
                                continue;
                            }
                        }
                    }
                } catch (e) {
                    console.error('URLhaus ClamAV error:', e);
                    return { 
                        verdict: 'Error', 
                        error: `URLhaus ClamAV: ${e.message}`,
                        source: 'URLhaus'
                    };
                }
            }

            cache.lastPull = Date.now();
            cache.pullCount++;
            saveCache();
            return { 
                verdict, 
                details,
                source: 'URLhaus'
            };
        } catch (e) {
            console.error('URLhaus text list error:', e);
            return { 
                verdict: 'Error', 
                error: `URLhaus text list: ${e.message}`,
                source: 'URLhaus'
            };
        }
    }

    if (cache.urls.size === 0) {
        console.log('Rate limit hit and cache empty');
        return { 
            verdict: 'Error', 
            error: 'URLhaus rate limit reached (5/day) and no cached data available',
            source: 'URLhaus'
        };
    }

    console.log('Rate limit hit, using cached data');
    return { 
        verdict: 'Safe',
        details: 'Not found in cached URLhaus data',
        source: 'URLhaus'
    };
}

async function checkVirusTotal(url, apiKey) {
    const urlId = btoa(url).replace(/=/g, '');
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
            headers: { 'x-apikey': apiKey }
        });
        const data = await response.json();
        if (data.data) {
            const stats = data.data.attributes.last_analysis_stats;
            return {
                verdict: stats.malicious > 0 ? 'Malicious' : 'Safe',
                details: stats,
                source: 'VirusTotal'
            };
        }
        return { 
            verdict: 'Unknown', 
            details: 'No data available',
            source: 'VirusTotal'
        };
    } catch (e) {
        throw new Error(`API request failed: ${e.message}`);
    }
}

async function checkGoogleSafeBrowsing(url, apiKey) {
    console.log('Sending GSB request for URL:', url, 'API key (obfuscated):', apiKey ? '****' + apiKey.slice(-4) : 'None');
    if (!url.startsWith('http')) {
        console.log('Non-HTTP URL, skipping GSB check:', url);
        return {
            verdict: 'Unknown',
            details: { message: 'Non-HTTP URL, GSB check skipped' },
            source: 'Google Safe Browsing'
        };
    }
    try {
        // Validate API key format (alphanumeric, 20+ characters)
        if (!apiKey || !/^[a-zA-Z0-9_-]{20,}$/.test(apiKey)) {
            throw new Error('Invalid or missing API key');
        }

        const payload = {
            client: {
                clientId: 'areumsec',
                clientVersion: '1.0.1'
            },
            threatInfo: {
                threatTypes: [
                    'MALWARE',
                    'SOCIAL_ENGINEERING',
                    'UNWANTED_SOFTWARE',
                    'POTENTIALLY_HARMFUL_APPLICATION'
                ],
                platformTypes: ['ANY_PLATFORM'],
                threatEntryTypes: ['URL'],
                threatEntries: [{ url }]
            }
        };
        console.log('GSB request payload:', JSON.stringify(payload, null, 2));

        const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            signal: AbortSignal.timeout(10000) // 10s timeout
        });

        console.log('GSB response status:', response.status, 'OK:', response.ok);

        if (!response.ok) {
            let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
            if (response.status === 400) errorMessage = 'Bad request, check payload';
            else if (response.status === 401 || response.status === 403) errorMessage = 'Invalid or unauthorized API key';
            else if (response.status === 429) errorMessage = 'Rate limit exceeded';
            throw new Error(errorMessage);
        }

        const data = await response.json();
        console.log('GSB response data:', JSON.stringify(data, null, 2));

        return {
            verdict: data.matches && data.matches.length > 0 ? 'Malicious' : 'Safe',
            details: data.matches || { message: 'No threats detected' },
            source: 'Google Safe Browsing'
        };
    } catch (e) {
        console.error('GSB request failed:', e.message);
        throw new Error(`API request failed: ${e.message}`);
    }
}