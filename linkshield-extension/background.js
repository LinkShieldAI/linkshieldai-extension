/**
 * ============================================================================
 * LinkShield Background Service Worker
 * ============================================================================
 * 
 * A Chrome extension that provides real-time malicious link protection.
 * Intercepts navigation events and scans URLs before allowing page loads.
 * 
 * Features:
 * - Parallel NSFW and malicious content scanning
 * - Intelligent retry logic with exponential backoff
 * - In-memory caching to reduce API calls
 * - Rate limiting protection
 * - Whitelist/trust list support
 * - Failed scan tracking to prevent infinite loops
 * 
 * @version 1.1.0
 * @author LinkShield Team
 * ============================================================================
 */

console.log("LinkShield: Service Worker Loaded v1.1.0");

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
    // API endpoints (using GET with query parameters as per API spec)
    API_ENDPOINT: 'https://api.linkshieldai.com/',
    NSFW_ENDPOINT: 'https://api.linkshieldai.com/nsfw/site',
    
    // Timing configuration
    CACHE_DURATION: 24 * 60 * 60 * 1000,      // 24 hours in milliseconds
    API_TIMEOUT: 15000,                        // 15 second timeout per request
    MAX_RETRIES: 5,                            // Maximum retry attempts
    RETRY_DELAY_BASE: 1000,                    // Base delay for exponential backoff (1 second)
    TEMPORARY_ALLOW_DURATION: 30000,           // 30 seconds for page to load
    FAILED_SCAN_COOLDOWN: 5 * 60 * 1000,      // 5 minute cooldown after max failures
    
    // Rate limiting
    RATE_LIMIT: {
        MAX_REQUESTS: 100,                     // Max requests per window
        WINDOW_MS: 60 * 60 * 1000             // 1 hour window
    },
    
    // API response mappings (based on actual API spec)
    RESPONSES: {
        MALICIOUS: {
            SAFE: ['likely safe', 'Safe', 'safe', 'The system didn\'t detect anything malicious', 'The system didn\'t detect anything malicious.'],
            MALICIOUS: ['Might be malicious', 'malicious', 'Malicious']
        },
        NSFW: {
            SAFE: ['False', false, 'false', 'Safe', 'safe'],
            NSFW: ['True', true, 'true', 'NSFW', 'nsfw']
        }
    }
};

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

/**
 * In-memory cache for scan results
 * Structure: Map<url, { result: 'safe'|'malicious'|'nsfw', timestamp: number }>
 */
const scanCache = new Map();

/**
 * Failed scan tracker - prevents infinite retry loops
 * Structure: Map<url, { attempts: number, lastAttempt: timestamp, errors: string[] }>
 */
const failedScans = new Map();

/**
 * Rate limiting tracker
 * Structure: { timestamps: number[] }
 */
const rateLimitTracker = {
    timestamps: []
};

/**
 * Temporary allow list for one-time bypasses
 * Structure: Set<url>
 */
const temporaryAllowList = new Set();

// ============================================================================
// INITIALIZATION & LIFECYCLE
// ============================================================================

chrome.runtime.onInstalled.addListener((details) => {
    console.log(`LinkShield: ${details.reason === 'install' ? 'Installed' : 'Updated'}`, details.reason);
    
    if (details.reason === 'install') {
        // First install - open setup page
        chrome.runtime.openOptionsPage();
        
        // Set badge to remind user to add API key
        chrome.action.setBadgeText({ text: "!" });
        chrome.action.setBadgeBackgroundColor({ color: "#FFA500" });
    }
    
    if (details.reason === 'update') {
        // Clear old cache on updates
        clearOldCache();
        failedScans.clear();
        console.log("LinkShield: Cache cleared after update");
    }
});

// ============================================================================
// URL NAVIGATION INTERCEPTION
// ============================================================================

/**
 * Main navigation interceptor - evaluates URLs before page loads
 * This is the core security mechanism of the extension
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only intercept main frame navigations (not iframes, etc.)
    if (details.frameId !== 0) return;
    
    const url = details.url;
    const warningPageUrl = chrome.runtime.getURL("warning.html");
    
    // Skip non-HTTP URLs and our own warning page
    if (!url.startsWith('http') || url.startsWith(warningPageUrl)) {
        return;
    }
    
    // Check temporary allow list first (user just clicked "continue")
    if (temporaryAllowList.has(url)) {
        console.log("LinkShield: Allowing temporarily bypassed URL:", url);
        temporaryAllowList.delete(url);
        return;
    }
    
    // Skip common safe URLs to reduce API load
    if (isCommonSafeUrl(url)) {
        console.log("LinkShield: Skipping common safe URL:", url);
        return;
    }
    
    console.log("LinkShield: Evaluating URL:", url);
    
    // Check whitelist
    const isTrusted = await isTrustedSite(url);
    if (isTrusted) {
        console.log("LinkShield: URL is whitelisted");
        updateBadge('safe', details.tabId);
        return;
    }
    
    // Check cache
    const cached = getCachedResult(url);
    if (cached) {
        console.log(`LinkShield: Cache hit - ${cached.result}`);
        handleCachedResult(cached.result, url, details.tabId);
        return;
    }
    
    // Check if URL has exceeded failure threshold
    if (shouldSkipDueToFailures(url)) {
        console.log("LinkShield: URL in cooldown period after repeated failures");
        updateBadge('error', details.tabId);
        return;
    }
    
    console.log("LinkShield: Cache miss - redirecting to scanning page");
    
    // Redirect to scanning page (prevents malicious site from loading)
    chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL(
            `warning.html?url=${encodeURIComponent(url)}&scan=1&tabId=${details.tabId}`
        )
    });
    
}, { 
    url: [
        { urlMatches: 'http://*/*' }, 
        { urlMatches: 'https://*/*' }
    ] 
});

/**
 * Handle cached scan results
 */
function handleCachedResult(result, url, tabId) {
    switch (result) {
        case 'safe':
            updateBadge('safe', tabId);
            break;
        case 'nsfw':
            updateBadge('nsfw', tabId);
            chrome.tabs.update(tabId, {
                url: chrome.runtime.getURL(
                    `warning.html?url=${encodeURIComponent(url)}&type=nsfw&tabId=${tabId}`
                )
            });
            break;
        case 'malicious':
            updateBadge('blocked', tabId);
            chrome.tabs.update(tabId, {
                url: chrome.runtime.getURL(
                    `warning.html?url=${encodeURIComponent(url)}&type=malicious&tabId=${tabId}`
                )
            });
            break;
    }
}

// ============================================================================
// PARALLEL SCANNING ENGINE
// ============================================================================

/**
 * Perform NSFW and malicious scans in parallel for maximum efficiency
 * 
 * @param {string} url - URL to scan
 * @param {string} apiKey - User's API key
 * @returns {Promise<{result: string, details: object}>}
 */
async function scanUrlParallel(url, apiKey) {
    const nsfwEnabled = await isNsfwProtectionEnabled();
    
    try {
        console.log(`LinkShield: Starting parallel scan for: ${url}`);
        
        // Build array of scan promises
        const scanPromises = [
            scanUrlWithRetry(url, apiKey, 'malicious')
        ];
        
        if (nsfwEnabled) {
            scanPromises.push(scanUrlWithRetry(url, apiKey, 'nsfw'));
        }
        
        // Execute all scans in parallel
        const results = await Promise.all(scanPromises);
        
        const maliciousResult = results[0];
        const nsfwResult = nsfwEnabled ? results[1] : { result: 'safe', attempts: 0 };
        
        console.log('LinkShield: Scan complete', {
            malicious: maliciousResult.result,
            nsfw: nsfwResult.result,
            maliciousAttempts: maliciousResult.attempts,
            nsfwAttempts: nsfwResult.attempts
        });
        
        // Prioritize threats: malicious > nsfw > safe
        if (maliciousResult.result === 'malicious') {
            return { 
                result: 'malicious', 
                details: { maliciousResult, nsfwResult }
            };
        }
        
        if (nsfwResult.result === 'nsfw') {
            return { 
                result: 'nsfw', 
                details: { maliciousResult, nsfwResult }
            };
        }
        
        // Handle error cases
        if (maliciousResult.result === 'error' && nsfwResult.result === 'error') {
            trackFailedScan(url, 'Both scans failed');
            return { 
                result: 'error', 
                details: { maliciousResult, nsfwResult }
            };
        }
        
        // Partial success - if NSFW passed but malicious failed, allow through with warning
        if (maliciousResult.result === 'error' && nsfwResult.result === 'safe') {
            console.warn('LinkShield: Malicious scan failed but NSFW passed - allowing through');
            trackFailedScan(url, 'Malicious scan failed');
            return { 
                result: 'safe', 
                details: { 
                    warning: 'Malicious scan failed',
                    maliciousResult, 
                    nsfwResult 
                }
            };
        }
        
        // Both safe
        return { 
            result: 'safe', 
            details: { maliciousResult, nsfwResult }
        };
        
    } catch (error) {
        console.error('LinkShield: Parallel scan error:', error);
        trackFailedScan(url, error.message);
        return { 
            result: 'error', 
            details: { error: error.message } 
        };
    }
}

/**
 * Scan with automatic retry logic and exponential backoff
 * 
 * @param {string} url - URL to scan
 * @param {string} apiKey - API key
 * @param {string} scanType - 'malicious' or 'nsfw'
 * @returns {Promise<{result: string, attempts: number, error?: any}>}
 */
async function scanUrlWithRetry(url, apiKey, scanType = 'malicious') {
    let attempts = 0;
    let lastError = null;
    
    while (attempts < CONFIG.MAX_RETRIES) {
        attempts++;
        
        try {
            console.log(`LinkShield: ${scanType} scan attempt ${attempts}/${CONFIG.MAX_RETRIES}`);
            
            // Perform scan
            let result;
            if (scanType === 'nsfw') {
                result = await scanUrlForNsfwWithTimeout(url, apiKey);
            } else {
                result = await scanUrlWithTimeout(url, apiKey);
            }
            
            // Success - return immediately
            if (result !== 'error') {
                console.log(`LinkShield: ${scanType} scan succeeded on attempt ${attempts}`);
                return { result, attempts };
            }
            
            lastError = 'Scan returned error status';
            
        } catch (error) {
            lastError = error;
            console.error(`LinkShield: ${scanType} scan attempt ${attempts} failed:`, error.message);
        }
        
        // Wait before retry (exponential backoff)
        if (attempts < CONFIG.MAX_RETRIES) {
            const delay = CONFIG.RETRY_DELAY_BASE * Math.pow(2, attempts - 1);
            console.log(`LinkShield: Waiting ${delay}ms before retry...`);
            await sleep(delay);
        }
    }
    
    // All retries exhausted
    console.error(`LinkShield: ${scanType} scan failed after ${CONFIG.MAX_RETRIES} attempts:`, lastError);
    return { 
        result: 'error', 
        attempts, 
        error: lastError?.message || String(lastError)
    };
}

// ============================================================================
// API COMMUNICATION - MALICIOUS SCAN
// ============================================================================

/**
 * Scan URL for malicious content with timeout protection
 */
async function scanUrlWithTimeout(url, apiKey) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.API_TIMEOUT);

    try {
        const result = await scanUrl(url, apiKey, controller.signal);
        return result;
    } catch (error) {
        if (error.name === 'AbortError') {
            console.error(`LinkShield: Malicious scan timeout after ${CONFIG.API_TIMEOUT}ms`);
        }
        return 'error';
    } finally {
        clearTimeout(timeoutId);
    }
}

/**
 * Core malicious URL scanning function
 * API Spec: GET https://api.linkshieldai.com/?key={key}&url={url}
 */
async function scanUrl(url, apiKey, signal) {
    try {
        // Build API URL per specification (GET with query params)
        const endpoint = `${CONFIG.API_ENDPOINT}?key=${encodeURIComponent(apiKey)}&url=${encodeURIComponent(url)}`;

        const response = await fetch(endpoint, {
            method: 'GET',
            signal
        });

        console.log("LinkShield: Malicious API Response Status:", response.status);

        // Handle HTTP errors
        if (!response.ok) {
            // Try to get error message from response
            let errorMsg = `HTTP ${response.status}`;
            try {
                const errorText = await response.text();
                // Check if it's JSON with an error field
                try {
                    const errorJson = JSON.parse(errorText);
                    if (errorJson.Error) {
                        errorMsg = `API Error: ${errorJson.Error}`;
                    }
                } catch {
                    // Not JSON, log raw error (truncated)
                    console.error("LinkShield: API error response:", errorText.substring(0, 200));
                }
            } catch {
                // Could not read error body
            }
            
            throw new Error(errorMsg);
        }

        // Parse response
        const data = await response.json();
        
        // Check for API-level errors
        if (data.Error) {
            console.error("LinkShield: API returned error:", data.Error);
            throw new Error(data.Error);
        }

        // Parse result based on API spec
        const result = data.result;
        
        // Check if malicious
        if (CONFIG.RESPONSES.MALICIOUS.MALICIOUS.includes(result)) {
            return 'malicious';
        }
        
        // Check if safe
        if (CONFIG.RESPONSES.MALICIOUS.SAFE.includes(result)) {
            return 'safe';
        }
        
        // Unknown response - default to safe to avoid false positives
        console.warn("LinkShield: Unknown malicious API result:", result, "- treating as safe");
        return 'safe';
        
    } catch (error) {
        if (error.name === 'AbortError') {
            throw error; // Let timeout handler deal with it
        }
        console.error("LinkShield: Malicious scan fetch failed:", error.message);
        return 'error';
    }
}

// ============================================================================
// API COMMUNICATION - NSFW SCAN
// ============================================================================

/**
 * Scan URL for NSFW content with timeout protection
 */
async function scanUrlForNsfwWithTimeout(url, apiKey) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.API_TIMEOUT);

    try {
        const result = await scanUrlForNsfw(url, apiKey, controller.signal);
        return result;
    } catch (error) {
        if (error.name === 'AbortError') {
            console.error(`LinkShield: NSFW scan timeout after ${CONFIG.API_TIMEOUT}ms`);
        }
        return 'error';
    } finally {
        clearTimeout(timeoutId);
    }
}

/**
 * Core NSFW URL scanning function
 * API Spec: GET https://api.linkshieldai.com/nsfw/site?key={key}&url={url}
 */
async function scanUrlForNsfw(url, apiKey, signal) {
    try {
        // Build API URL per specification (GET with query params)
        const endpoint = `${CONFIG.NSFW_ENDPOINT}?key=${encodeURIComponent(apiKey)}&url=${encodeURIComponent(url)}`;

        const response = await fetch(endpoint, {
            method: 'GET',
            signal
        });

        console.log("LinkShield: NSFW API Response Status:", response.status);

        // Handle HTTP errors
        if (!response.ok) {
            let errorMsg = `HTTP ${response.status}`;
            try {
                const errorText = await response.text();
                try {
                    const errorJson = JSON.parse(errorText);
                    if (errorJson.Error) {
                        errorMsg = `API Error: ${errorJson.Error}`;
                    }
                } catch {
                    console.error("LinkShield: NSFW API error response:", errorText.substring(0, 200));
                }
            } catch {
                // Could not read error body
            }
            
            throw new Error(errorMsg);
        }

        // Parse response
        const data = await response.json();
        
        // Check for API-level errors
        if (data.Error) {
            console.error("LinkShield: NSFW API returned error:", data.Error);
            throw new Error(data.Error);
        }

        // Parse result based on API spec
        const result = data.result;
        
        // Check if NSFW
        if (CONFIG.RESPONSES.NSFW.NSFW.includes(result)) {
            return 'nsfw';
        }
        
        // Check if safe
        if (CONFIG.RESPONSES.NSFW.SAFE.includes(result)) {
            return 'safe';
        }
        
        // Unknown response - default to safe
        console.warn("LinkShield: Unknown NSFW API result:", result, "- treating as safe");
        return 'safe';
        
    } catch (error) {
        if (error.name === 'AbortError') {
            throw error;
        }
        console.error("LinkShield: NSFW scan fetch failed:", error.message);
        return 'error';
    }
}

// ============================================================================
// CACHE MANAGEMENT
// ============================================================================

/**
 * Cache a scan result
 */
function cacheResult(url, result) {
    scanCache.set(url, {
        result: result,
        timestamp: Date.now()
    });
    
    console.log(`LinkShield: Cached result for ${url}: ${result}`);
    
    // Clear from failed scans on success
    if (result !== 'error') {
        failedScans.delete(url);
    }
}

/**
 * Retrieve cached result if still valid
 */
function getCachedResult(url) {
    const cached = scanCache.get(url);
    
    if (!cached) return null;
    
    // Check expiration
    const age = Date.now() - cached.timestamp;
    if (age > CONFIG.CACHE_DURATION) {
        scanCache.delete(url);
        console.log(`LinkShield: Cache expired for ${url}`);
        return null;
    }
    
    return cached;
}

/**
 * Clear expired cache entries
 */
function clearOldCache() {
    const now = Date.now();
    let cleared = 0;
    
    for (const [url, data] of scanCache.entries()) {
        const age = now - data.timestamp;
        if (age > CONFIG.CACHE_DURATION) {
            scanCache.delete(url);
            cleared++;
        }
    }
    
    if (cleared > 0) {
        console.log(`LinkShield: Cleared ${cleared} expired cache entries`);
    }
}

// ============================================================================
// FAILED SCAN TRACKING
// ============================================================================

/**
 * Track a failed scan to prevent infinite retry loops
 */
function trackFailedScan(url, errorMessage) {
    const existing = failedScans.get(url);
    
    if (existing) {
        existing.attempts++;
        existing.lastAttempt = Date.now();
        existing.errors.push(errorMessage);
        failedScans.set(url, existing);
    } else {
        failedScans.set(url, {
            attempts: 1,
            lastAttempt: Date.now(),
            errors: [errorMessage]
        });
    }
    
    const info = failedScans.get(url);
    console.log(`LinkShield: Tracked failed scan for ${url}: ${info.attempts} total failures`);
}

/**
 * Check if URL should be skipped due to repeated failures
 */
function shouldSkipDueToFailures(url) {
    const failedInfo = failedScans.get(url);
    
    if (!failedInfo || failedInfo.attempts < CONFIG.MAX_RETRIES) {
        return false;
    }
    
    const timeSinceLastAttempt = Date.now() - failedInfo.lastAttempt;
    
    if (timeSinceLastAttempt < CONFIG.FAILED_SCAN_COOLDOWN) {
        return true; // Still in cooldown
    }
    
    // Cooldown expired - reset
    console.log(`LinkShield: Cooldown expired for ${url}, resetting failure counter`);
    failedScans.delete(url);
    return false;
}

// ============================================================================
// RATE LIMITING
// ============================================================================

/**
 * Check if rate limit has been exceeded
 */
function isRateLimited() {
    const now = Date.now();
    
    // Remove old timestamps outside the window
    rateLimitTracker.timestamps = rateLimitTracker.timestamps.filter(
        timestamp => (now - timestamp) < CONFIG.RATE_LIMIT.WINDOW_MS
    );
    
    // Check limit
    if (rateLimitTracker.timestamps.length >= CONFIG.RATE_LIMIT.MAX_REQUESTS) {
        console.warn(`LinkShield: Rate limit exceeded (${CONFIG.RATE_LIMIT.MAX_REQUESTS} requests per hour)`);
        return true;
    }
    
    // Add current request
    rateLimitTracker.timestamps.push(now);
    return false;
}

// ============================================================================
// WHITELIST / TRUST MANAGEMENT
// ============================================================================

/**
 * Check if URL is in user's whitelist
 */
async function isTrustedSite(url) {
    return new Promise((resolve) => {
        chrome.storage.local.get([url], (data) => {
            resolve(data[url] === true);
        });
    });
}

// ============================================================================
// URL FILTERING
// ============================================================================

/**
 * Check if URL belongs to a commonly safe domain
 * This reduces API load by skipping well-known safe sites
 */
function isCommonSafeUrl(url) {
    try {
        const urlObj = new URL(url);
        
        const safeDomains = [
        "google.com",
        "youtube.com",
        "facebook.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "reddit.com",
        "wikipedia.org",
        "github.com",
        "stackoverflow.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "netflix.com",
        "spotify.com",
        "twitch.tv",
        "discord.com",
        "slack.com",
        "zoom.us",
        "dropbox.com",
        "drive.google.com",
        "docs.google.com",
        "mail.google.com",
        "outlook.com",
        "live.com",
        "office.com",
        "adobe.com",
        "canva.com",
        "figma.com",
        "notion.so",
        "trello.com",
        "asana.com",
        "monday.com",
        "atlassian.net",
        "jira.com",
        "confluence.com",
        "bitbucket.org",
        "gitlab.com",
        "npmjs.com",
        "pypi.org",
        "crates.io",
        "packagist.org",
        "rubygems.org",
        "maven.org",
        "nuget.org",
        "cloudflare.com",
        "aws.amazon.com",
        "azure.microsoft.com",
        "cloud.google.com",
        "heroku.com",
        "vercel.com",
        "netlify.com",
        "digitalocean.com",
        "linode.com",
        "vultr.com",
        "hetzner.com",
        "ovh.com",
        "scaleway.com",
        "stripe.com",
        "paypal.com",
        "square.com",
        "shopify.com",
        "wix.com",
        "wordpress.com",
        "medium.com",
        "substack.com",
        "patreon.com",
        "gofundme.com",
        "kickstarter.com",
        "indiegogo.com",
        "ebay.com",
        "etsy.com",
        "aliexpress.com",
        "alibaba.com",
        "walmart.com",
        "target.com",
        "bestbuy.com",
        "homedepot.com",
        "lowes.com",
        "ikea.com",
        "wayfair.com",
        "overstock.com",
        "booking.com",
        "airbnb.com",
        "expedia.com",
        "tripadvisor.com",
        "hotels.com",
        "kayak.com",
        "skyscanner.com",
        "uber.com",
        "lyft.com",
        "doordash.com",
        "grubhub.com",
        "ubereats.com",
        "postmates.com",
        "instacart.com",
        "gopuff.com",
        "yelp.com",
        "opentable.com",
        "resy.com",
        "seamless.com",
        "caviar.com",
        "grubhub.com",
        "bluevine.com",
        "brex.com",
        "ramp.com",
        "mercury.com",
        "novo.co",
        "lili.co",
        "axos.com",
        "chime.com",
        "varo.com",
        "current.com",
        "ally.com",
        "capitalone.com",
        "chase.com",
        "wellsfargo.com",
        "bankofamerica.com",
        "citi.com",
        "usbank.com",
        "pnc.com",
        "truist.com",
        "regions.com",
        "santander.com",
        "bbt.com",
        "suntrust.com",
        "tdbank.com",
        "citizensbank.com",
        "huntington.com",
        "fifththird.com",
        "mandt.com",
        "keybank.com",
        "ubs.com",
        "schwab.com",
        "fidelity.com",
        "vanguard.com",
        "etrade.com",
        "tdameritrade.com",
        "robinhood.com",
        "webull.com",
        "m1finance.com",
        "acorns.com",
        "stash.com",
        "betterment.com",
        "wealthfront.com",
        "sofi.com",
        "marcus.com",
        "discover.com",
        "americanexpress.com",
        "barclays.com",
        "synchrony.com",
        "ge.com",
        "ford.com",
        "gm.com",
        "tesla.com",
        "toyota.com",
        "honda.com",
        "nissan.com",
        "bmw.com",
        "mercedes-benz.com",
        "audi.com",
        "volkswagen.com",
        "porsche.com",
        "ferrari.com",
        "lamborghini.com",
        "maserati.com",
        "bentley.com",
        "rollsroyce.com",
        "jaguar.com",
        "landrover.com",
        "jeep.com",
        "ram.com",
        "dodge.com",
        "chrysler.com",
        "buick.com",
        "cadillac.com",
        "chevrolet.com",
        "gmc.com",
        "hyundai.com",
        "kia.com",
        "mazda.com",
        "mitsubishi.com",
        "subaru.com",
        "volvo.com",
        "polestar.com",
        "rivian.com",
        "lucid.com",
        "nio.com",
        "xpeng.com",
        "byd.com",
        "geely.com",
        "greatwall.com",
        "firstbank.com",
        "unionbank.com",
        "wema.com",
        "poloniex.com",
        "binance.com",
        "coinbase.com",
        "kraken.com",
        "bitfinex.com",
        "bittrex.com",
        "huobi.com",
        "okex.com",
        "gemini.com",
        "bitstamp.net",
        "kucoin.com",
        "bitmex.com",
        "deribit.com",
        "bybit.com",
        "ftx.com",
        "crypto.com",
        "coinmarketcap.com",
        "coingecko.com",
        "chainalysis.com",
        "elliptic.co",
        "ciphertrace.com",
        "blockchain.com",
        "blockchair.com",
        "blockstream.info",
        "etherscan.io",
        "bscscan.com",
        "polygonscan.com",
        "solscan.io",
        "tronscan.org",
        "cardanoscan.io",
        "tezos.com",
        "instagram.com",
        "urlscan.io",
        "virustotal.com",
        "phishtank.com",
        "urlvoid.com",
        "sucuri.net",
        "sitecheck.sucuri.net",
        "webroot.com",
        "norton.com",
        "mcafee.com",
        "kaspersky.com",
        "avast.com",
        "avg.com",
        "bitdefender.com",
        "trendmicro.com",
        "malwarebytes.com",
        "eset.com",
        "paloaltonetworks.com",
        "crowdstrike.com",
        "cylance.com",
        "sentinelone.com",
        "carbonblack.com",
        "sophos.com",
        "kick.com",
        "rumble.com",
        "dailymotion.com",
        "bitchute.com",
        "brighteon.com",
        "chat.openai.com",
        "platform.openai.com",
        "azure.com",
        "cloud.google.com",
        "aws.amazon.com",
        "huggingface.co",
        "replicate.com",
        "stability.ai",
        "midjourney.com",
        "claude.ai",
        "deepmind.com",
        "anthropic.com",
        "cohere.ai",
        "ai21.com",
        "gemini.google.com"
        ];
        
        return safeDomains.some(domain => 
            urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain)
        );
    } catch {
        return false;
    }
}

// ============================================================================
// STORAGE UTILITIES
// ============================================================================

/**
 * Retrieve API key from storage
 */
function getApiKey() {
    return new Promise(resolve => {
        chrome.storage.sync.get(['apiKey'], (data) => {
            resolve(data.apiKey || null);
        });
    });
}

/**
 * Check if NSFW protection is enabled
 */
function isNsfwProtectionEnabled() {
    return new Promise(resolve => {
        chrome.storage.sync.get(['nsfwProtection'], (data) => {
            resolve(data.nsfwProtection === true);
        });
    });
}

/**
 * Log blocked malicious site
 */
function logBlockedSite(url) {
    chrome.storage.local.get(['blockedHistory'], (data) => {
        const history = data.blockedHistory || [];
        history.unshift({
            url: url,
            timestamp: Date.now(),
            type: 'malicious'
        });
        
        // Keep only last 100 entries
        if (history.length > 100) {
            history.pop();
        }
        
        chrome.storage.local.set({ blockedHistory: history });
    });
}

/**
 * Log blocked NSFW site
 */
function logNsfwSite(url) {
    chrome.storage.local.get(['nsfwHistory'], (data) => {
        const history = data.nsfwHistory || [];
        history.unshift({
            url: url,
            timestamp: Date.now(),
            type: 'nsfw'
        });
        
        // Keep only last 100 entries
        if (history.length > 100) {
            history.pop();
        }
        
        chrome.storage.local.set({ nsfwHistory: history });
    });
}

// ============================================================================
// UI UPDATES
// ============================================================================

/**
 * Update extension badge
 */
function updateBadge(status, tabId) {
    const badges = {
        'safe': { text: '✓', color: '#4CAF50' },
        'malicious': { text: '✗', color: '#F44336' },
        'blocked': { text: '!', color: '#F44336' },
        'nsfw': { text: '18+', color: '#FF9800' },
        'scanning': { text: '...', color: '#2196F3' },
        'error': { text: '?', color: '#FF9800' },
        'no-key': { text: 'KEY', color: '#FF5722' },
        'rate-limit': { text: 'RATE', color: '#9E9E9E' }
    };
    
    const badge = badges[status] || badges['error'];
    
    if (tabId) {
        chrome.action.setBadgeText({ text: badge.text, tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: badge.color, tabId: tabId });
    } else {
        chrome.action.setBadgeText({ text: badge.text });
        chrome.action.setBadgeBackgroundColor({ color: badge.color });
    }
    
    // Auto-clear non-critical badges
    if (['safe', 'scanning'].includes(status)) {
        setTimeout(() => {
            chrome.action.setBadgeText({ text: '', tabId: tabId });
        }, 3000);
    }
}

/**
 * Show browser notification
 */
function showNotification(title, message) {
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'images/lsa128.png',
        title: title,
        message: message,
        priority: 2
    });
}

// ============================================================================
// MESSAGE HANDLERS (Communication with popup/warning pages)
// ============================================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    
    // Validate API key
    if (request.action === 'validateApiKey') {
        validateApiKey(request.apiKey)
            .then(isValid => sendResponse({ valid: isValid }))
            .catch(error => {
                console.error('API key validation error:', error);
                sendResponse({ valid: false });
            });
        return true; // Required for async response
    }
    
    // Clear cache
    if (request.action === 'clearCache') {
        scanCache.clear();
        failedScans.clear();
        console.log("LinkShield: Cache cleared manually");
        sendResponse({ success: true });
        return;
    }
    
    // Get statistics
    if (request.action === 'getStats') {
        sendResponse({
            cacheSize: scanCache.size,
            requestsInWindow: rateLimitTracker.timestamps.length,
            failedScans: failedScans.size
        });
        return;
    }
    
    // Temporarily allow URL
    if (request.action === 'allowOnce') {
        const url = request.url;
        console.log('LinkShield: Temporarily allowing:', url);
        
        temporaryAllowList.add(url);
        
        // Remove after timeout
        setTimeout(() => {
            temporaryAllowList.delete(url);
            console.log('LinkShield: Removed temporary allow for:', url);
        }, CONFIG.TEMPORARY_ALLOW_DURATION);
        
        sendResponse({ success: true });
        return;
    }
    
    // Perform scan (called from warning page)
    if (request.action === 'scanUrl') {
        const { url } = request;
        
        (async () => {
            try {
                // Validate API key exists
                const apiKey = await getApiKey();
                if (!apiKey) {
                    sendResponse({ result: 'no-key' });
                    return;
                }
                
                // Check rate limit
                if (isRateLimited()) {
                    sendResponse({ result: 'rate-limited' });
                    return;
                }
                
                // Perform parallel scans
                const scanResult = await scanUrlParallel(url, apiKey);
                
                // Cache successful results
                if (scanResult.result !== 'error') {
                    cacheResult(url, scanResult.result);
                }
                
                // Log blocked sites
                if (scanResult.result === 'malicious') {
                    logBlockedSite(url);
                } else if (scanResult.result === 'nsfw') {
                    logNsfwSite(url);
                }
                
                sendResponse({ 
                    result: scanResult.result,
                    details: scanResult.details 
                });
                
            } catch (error) {
                console.error('LinkShield: Scan request error:', error);
                sendResponse({ result: 'error', error: error.message });
            }
        })();
        
        return true; // Required for async response
    }
    
    // Clear badge
    if (request.action === 'clearBadge') {
        chrome.action.setBadgeText({ text: '' });
        sendResponse({ success: true });
        return;
    }
});

// ============================================================================
// API KEY VALIDATION
// ============================================================================

/**
 * Validate API key by making a test request
 */
async function validateApiKey(apiKey) {
    try {
        // Test with a known safe URL
        const testUrl = 'https://example.com';
        const endpoint = `${CONFIG.API_ENDPOINT}?key=${encodeURIComponent(apiKey)}&url=${encodeURIComponent(testUrl)}`;
        
        const response = await fetch(endpoint, {
            method: 'GET'
        });
        
        // API key is valid if we don't get 401/403
        if (response.status === 401 || response.status === 403) {
            return false;
        }
        
        // If we get 200, validate we can parse the response
        if (response.ok) {
            try {
                await response.json();
                return true;
            } catch {
                return false;
            }
        }
        
        // Other status codes might indicate server issues, not invalid key
        // So we'll accept them as "valid key" for now
        return true;
        
    } catch (error) {
        console.error('API key validation error:', error);
        return false;
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Sleep utility for retry delays
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// BACKGROUND MAINTENANCE
// ============================================================================

/**
 * Periodic cleanup - runs every hour
 * Clears expired cache and old failed scan entries
 */
setInterval(() => {
    clearOldCache();
    
    // Clean up old failed scan entries (older than 1 hour)
    const now = Date.now();
    const oneHour = 60 * 60 * 1000;
    
    for (const [url, info] of failedScans.entries()) {
        if (now - info.lastAttempt > oneHour) {
            failedScans.delete(url);
        }
    }
    
    console.log(`LinkShield: Maintenance complete - Cache: ${scanCache.size}, Failed scans: ${failedScans.size}`);
}, 60 * 60 * 1000);

// ============================================================================
// END OF SERVICE WORKER
// ============================================================================
