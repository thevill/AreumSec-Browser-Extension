const cache = {
    urls: new Map(), // URLhaus cache (protocol-agnostic)
    phishingDBUrls: new Map(), // Phishing DB cache (protocol-agnostic)
    lastPull: 0,
    pullCount: 0,
    lastPullDay: 0,
    maxPullsPerDay: 5,
    pullInterval: 86400 * 1000 / 5 // ~4.8 hours
};

const CACHE_DURATION = 60 * 60 * 1000; // 1 hour
const RATE_LIMIT = {
    virustotal: { max: 4, window: 60 * 1000 },
    googleSafeBrowsing: { max: 10000, window: 24 * 60 * 60 * 1000 }
};
const requestCounts = { virustotal: { count: 0, lastReset: 0 }, googleSafeBrowsing: { count: 0, lastReset: 0 } };
const pendingChecks = new Set();

// Load cache
chrome.storage.local.get(['urlhausCache', 'phishingDBCache'], (data) => {
    if (!chrome.runtime.lastError) {
        if (data.urlhausCache) {
            cache.urls = new Map(data.urlhausCache.urls.map(url => [normalizeUrlWithoutProtocol(url), true]));
            cache.lastPull = data.urlhausCache.lastPull || 0;
            cache.pullCount = data.urlhausCache.pullCount || 0;
            cache.lastPullDay = data.urlhausCache.lastPullDay || 0;
            console.log('Loaded URLhaus cache:', cache.urls.size, 'URLs');
        }
        if (data.phishingDBCache) {
            cache.phishingDBUrls = new Map(data.phishingDBCache.urls.map(url => [normalizeUrlWithoutProtocol(url), true]));
            console.log('Loaded Phishing DB cache:', cache.phishingDBUrls.size, 'URLs');
        }
    } else {
        console.error('Error loading cache:', chrome.runtime.lastError);
    }
});

function saveCache() {
    chrome.storage.local.set({
        urlhausCache: {
            urls: Array.from(cache.urls.keys()),
            lastPull: cache.lastPull,
            pullCount: cache.pullCount,
            lastPullDay: cache.lastPullDay
        },
        phishingDBCache: {
            urls: Array.from(cache.phishingDBUrls.keys()),
            lastPull: cache.lastPull,
            pullCount: cache.pullCount,
            lastPullDay: cache.lastPullDay
        }
    }, () => {
        if (chrome.runtime.lastError) console.error('Error saving cache:', chrome.runtime.lastError);
        else console.log('Cache saved - URLhaus:', cache.urls.size, 'Phishing DB:', cache.phishingDBUrls.size, 'URLs');
    });
}

function canPull() {
    const now = Date.now();
    const currentDay = Math.floor(now / (24 * 60 * 60 * 1000));
    if (currentDay > cache.lastPullDay) {
        cache.pullCount = 0;
        cache.lastPullDay = currentDay;
        console.log('New day, reset pull count');
    }
    return cache.pullCount < cache.maxPullsPerDay && (now - cache.lastPull >= cache.pullInterval || cache.urls.size === 0 || cache.phishingDBUrls.size === 0);
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getResults") {
        chrome.storage.local.get(['urlSafetyResults', 'currentUrl'], (data) => {
            if (!data.currentUrl || data.currentUrl === normalizeUrl(request.url)) {
                sendResponse(data.urlSafetyResults || {});
            } else {
                sendResponse({});
            }
        });
        return true;
    }
    if (request.action === "checkUrl") {
        chrome.storage.sync.get(['vtApiKey', 'gsbApiKey'], (data) => {
            checkUrlSafety(request.url, data.vtApiKey, data.gsbApiKey)
                .then(() => {
                    console.log('Manual URL check completed for:', request.url);
                    sendResponse({ status: 'success' });
                })
                .catch(e => {
                    console.error('Manual URL check failed:', e);
                    sendResponse({ status: 'error', message: e.message });
                });
        });
        return true;
    }
});

// Clear results and cache on navigation
function clearStorage(url) {
    chrome.storage.local.get(null, (data) => {
        const keysToRemove = Object.keys(data).filter(k => k.startsWith('cache_') && k !== `cache_${normalizeUrl(url)}`);
        keysToRemove.push('urlSafetyResults');
        if (keysToRemove.length > 0) {
            chrome.storage.local.remove(keysToRemove, () => {
                if (chrome.runtime.lastError) console.error('Error clearing storage:', chrome.runtime.lastError);
                else console.log('Cleared storage:', keysToRemove);
            });
        }
    });
}

chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0 || details.url.includes('urlhaus.abuse.ch') || details.url.includes('raw.githubusercontent.com')) {
        console.log('Skipping navigation check for:', details.url);
        return;
    }
    const url = normalizeUrl(details.url);
    console.log('Navigation committed, checking URL:', url);
    clearStorage(url);
    chrome.storage.local.set({ currentUrl: url }, () => {
        chrome.storage.sync.get(['vtApiKey', 'gsbApiKey'], (data) => {
            checkUrlSafety(details.url, data.vtApiKey, data.gsbApiKey)
                .then(() => console.log('Automatic URL check completed for:', url))
                .catch(e => console.error('Automatic URL check failed:', e));
        });
    });
}, { url: [{ urlMatches: 'http://*/*' }, { urlMatches: 'https://*/*' }] });

chrome.webNavigation.onCompleted.addListener((details) => {
    if (details.frameId !== 0 || details.url.includes('urlhaus.abuse.ch') || details.url.includes('raw.githubusercontent.com')) {
        console.log('Skipping navigation completion for:', details.url);
        return;
    }
    const url = normalizeUrl(details.url);
    console.log('Navigation completed, updating current URL:', url);
    clearStorage(url);
    chrome.storage.local.set({ currentUrl: url });
}, { url: [{ urlMatches: 'http://*/*' }, { urlMatches: 'https://*/*' }] });

async function checkUrlSafety(url, vtApiKey, gsbApiKey) {
    const normalizedUrl = normalizeUrl(url);
    if (!isValidUrl(normalizedUrl) || pendingChecks.has(normalizedUrl)) {
        console.log('Skipping check for invalid or pending URL:', normalizedUrl);
        return;
    }

    pendingChecks.add(normalizedUrl);
    const cacheKey = `cache_${normalizedUrl}`;

    try {
        const cached = await getCachedResult(cacheKey);
        if (cached) {
            console.log('Using cached results for:', normalizedUrl);
            await saveResults(cached, cacheKey, normalizedUrl);
            notifyIfMalicious(cached); // Trigger notification for cached malicious results
            return;
        }

        const results = {};
        const now = Date.now();
        resetRateLimits(now);

        try {
            results.urlhaus = await checkUrlhaus(normalizedUrl);
        } catch (e) {
            console.error('URLhaus check failed:', e);
            results.urlhaus = { verdict: 'Error', error: `URLhaus: ${e.message}`, timestamp: now, source: 'URLhaus' };
        }

        try {
            results.phishingDB = await checkPhishingDB(normalizedUrl);
        } catch (e) {
            console.error('Phishing DB check failed:', e);
            results.phishingDB = { verdict: 'Error', error: `Phishing DB: ${e.message}`, timestamp: now, source: 'Phishing DB' };
        }

        await checkOtherServices(normalizedUrl, vtApiKey, gsbApiKey, results, now);
        await saveAndNotify(results, cacheKey, normalizedUrl, now);
    } catch (e) {
        console.error('URL safety check failed:', e);
        await saveErrorResult(normalizedUrl, `Safety check failed: ${e.message}`);
    } finally {
        pendingChecks.delete(normalizedUrl);
    }
}

async function saveErrorResult(url, errorMessage) {
    const cacheKey = `cache_${url}`;
    const results = {
        default: { verdict: 'Error', error: errorMessage, timestamp: Date.now(), source: 'AreumSec' }
    };
    await saveResults(results, cacheKey, url);
    notifyIfMalicious(results); // Check for notifications even on error results
}

function resetRateLimits(now) {
    for (const service of Object.keys(RATE_LIMIT)) {
        if (now - requestCounts[service].lastReset > RATE_LIMIT[service].window) {
            requestCounts[service].count = 0;
            requestCounts[service].lastReset = now;
            console.log(`Reset ${service} rate limit`);
        }
    }
}

async function checkOtherServices(url, vtApiKey, gsbApiKey, results, now) {
    const checks = [];
    if (vtApiKey && requestCounts.virustotal.count < RATE_LIMIT.virustotal.max) {
        checks.push(checkVirusTotal(url, vtApiKey).then(res => {
            results.virustotal = res;
            requestCounts.virustotal.count++;
        }).catch(e => {
            results.virustotal = { verdict: 'Error', error: `VirusTotal: ${e.message}`, timestamp: now, source: 'VirusTotal' };
        }));
    }
    if (gsbApiKey && requestCounts.googleSafeBrowsing.count < RATE_LIMIT.googleSafeBrowsing.max && url.startsWith('http')) {
        checks.push(checkGoogleSafeBrowsing(url, gsbApiKey).then(res => {
            results.googleSafeBrowsing = res;
            requestCounts.googleSafeBrowsing.count++;
        }).catch(e => {
            results.googleSafeBrowsing = { verdict: 'Error', error: `Google Safe Browsing: ${e.message}`, timestamp: now, source: 'Google Safe Browsing' };
        }));
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
        chrome.storage.local.set({ [cacheKey]: results, urlSafetyResults: results, currentUrl: url }, () => {
            if (chrome.runtime.lastError) console.error('Error saving results:', chrome.runtime.lastError);
            else console.log('Results saved for:', cacheKey, 'Results:', results);
            resolve();
        });
    });
}

function notifyIfMalicious(results) {
    console.log('Checking for malicious results:', results);
    if (Object.values(results).some(r => r.verdict === 'Malicious')) {
        console.log('Malicious URL detected, creating notification');
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icon48.png',
            title: 'AreumSec Alert',
            message: 'This URL may be unsafe! Check the popup for details.',
            priority: 2
        }, (notificationId) => {
            if (chrome.runtime.lastError) {
                console.error('Notification error:', chrome.runtime.lastError);
            } else {
                console.log('Notification created:', notificationId);
            }
        });
    } else {
        console.log('No malicious URL detected, no notification needed');
    }
}

async function getCachedResult(cacheKey) {
    return new Promise((resolve) => {
        chrome.storage.local.get([cacheKey], (result) => {
            if (result[cacheKey] && Date.now() - (result[cacheKey].urlhaus?.timestamp || result[cacheKey].phishingDB?.timestamp || result[cacheKey].virustotal?.timestamp || result[cacheKey].googleSafeBrowsing?.timestamp || 0) < CACHE_DURATION) {
                console.log('Cache hit for:', cacheKey);
                resolve(result[cacheKey]);
            } else {
                console.log('No valid cache for:', cacheKey);
                resolve(null);
            }
        });
    });
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

function normalizeUrlWithoutProtocol(url) {
    try {
        const urlObj = new URL(url);
        let normalized = `${urlObj.hostname}${urlObj.pathname}`;
        if (url.endsWith('/') && !normalized.endsWith('/')) normalized += '/';
        if (urlObj.port) normalized = `${urlObj.hostname}:${urlObj.port}${urlObj.pathname}`;
        return normalized.toLowerCase();
    } catch {
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
    const lowerUrl = normalizeUrlWithoutProtocol(url);
    if (cache.urls.has(lowerUrl)) {
        return { verdict: 'Malicious', details: 'Found in URLhaus cache', source: 'URLhaus' };
    }

    if (!canPull()) {
        return cache.urls.size === 0
            ? { verdict: 'Error', error: 'URLhaus rate limit reached (5/day) and no cache', source: 'URLhaus' }
            : { verdict: 'Safe', details: 'Not found in cached URLhaus data', source: 'URLhaus' };
    }

    try {
        const textResponse = await fetch('https://urlhaus.abuse.ch/downloads/text/', {
            signal: AbortSignal.timeout(15000),
            headers: { 'Accept': 'text/plain' }
        });
        if (!textResponse.ok) throw new Error(`HTTP ${textResponse.status}`);
        const text = await textResponse.text();
        const textLines = text.split('\n').filter(line => line.trim() && !line.startsWith('#') && isValidUrl(line));

        for (const line of textLines) {
            const normalizedLine = normalizeUrlWithoutProtocol(line);
            cache.urls.set(normalizedLine, true);
            if (normalizedLine === lowerUrl) {
                cache.lastPull = Date.now();
                cache.pullCount++;
                saveCache();
                return { verdict: 'Malicious', details: 'Found in URLhaus text list', source: 'URLhaus' };
            }
        }

        cache.lastPull = Date.now();
        cache.pullCount++;
        saveCache();
        return { verdict: 'Safe', details: 'Not found in URLhaus data', source: 'URLhaus' };
    } catch (e) {
        return { verdict: 'Error', error: `URLhaus: ${e.message}`, source: 'URLhaus' };
    }
}

async function checkPhishingDB(url) {
    const lowerUrl = normalizeUrlWithoutProtocol(url);
    if (cache.phishingDBUrls.has(lowerUrl)) {
        return { verdict: 'Malicious', details: 'Found in Phishing DB cache', source: 'Phishing DB' };
    }

    if (!canPull()) {
        return cache.phishingDBUrls.size === 0
            ? { verdict: 'Error', error: 'Phishing DB rate limit reached (5/day) and no cache', source: 'Phishing DB' }
            : { verdict: 'Safe', details: 'Not found in cached Phishing DB data', source: 'Phishing DB' };
    }

    const sources = [
        'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-links-ACTIVE.txt',
        'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-links-INACTIVE.txt',
        'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-links-NEW-today.txt'
    ];

    try {
        for (const source of sources) {
            const textResponse = await fetch(source, {
                signal: AbortSignal.timeout(15000),
                headers: { 'Accept': 'text/plain' }
            });
            if (!textResponse.ok) throw new Error(`HTTP ${textResponse.status} for ${source}`);
            const text = await textResponse.text();
            const textLines = text.split('\n').filter(line => line.trim() && !line.startsWith('#') && isValidUrl(line));

            for (const line of textLines) {
                const normalizedLine = normalizeUrlWithoutProtocol(line);
                cache.phishingDBUrls.set(normalizedLine, true);
                if (normalizedLine === lowerUrl) {
                    cache.lastPull = Date.now();
                    cache.pullCount++;
                    saveCache();
                    return { verdict: 'Malicious', details: `Found in Phishing DB list: ${source.split('/').pop()}`, source: 'Phishing DB' };
                }
            }
        }

        cache.lastPull = Date.now();
        cache.pullCount++;
        saveCache();
        return { verdict: 'Safe', details: 'Not found in Phishing DB data', source: 'Phishing DB' };
    } catch (e) {
        return { verdict: 'Error', error: `Phishing DB: ${e.message}`, source: 'Phishing DB' };
    }
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
        return { verdict: 'Unknown', details: 'No data available', source: 'VirusTotal' };
    } catch (e) {
        throw new Error(`API request failed: ${e.message}`);
    }
}

async function checkGoogleSafeBrowsing(url, apiKey) {
    if (!url.startsWith('http')) {
        return { verdict: 'Unknown', details: { message: 'Non-HTTP URL' }, source: 'Google Safe Browsing' };
    }
    try {
        const payload = {
            client: { clientId: 'areumsec', clientVersion: '1.0.1' },
            threatInfo: {
                threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                platformTypes: ['ANY_PLATFORM'],
                threatEntryTypes: ['URL'],
                threatEntries: [{ url }]
            }
        };
        const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            signal: AbortSignal.timeout(10000)
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        return {
            verdict: data.matches?.length > 0 ? 'Malicious' : 'Safe',
            details: data.matches || { message: 'No threats detected' },
            source: 'Google Safe Browsing'
        };
    } catch (e) {
        throw new Error(`API request failed: ${e.message}`);
    }
}