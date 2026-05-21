/**
 * LinkShield Warning Page
 * Displays security warnings and manages user decisions
 * Supports both malicious and NSFW warnings
 * NEW: Handles live scanning with loading state
 */

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    console.log("LinkShield Warning: Initializing...");
    
    // Get URL and parameters from query string
    const params = new URLSearchParams(window.location.search);
    const targetUrl = params.get('url');
    const warningType = params.get('type') || 'malicious'; // Default to malicious
    const scanMode = params.get('scan') === '1'; // Are we in scanning mode?
    
    if (!targetUrl) {
        // No URL provided - show error
        showError();
        return;
    }
    
    // SECURITY: Validate and sanitize URL
    if (!isValidUrl(targetUrl)) {
        console.error("Invalid URL provided:", targetUrl);
        showError();
        return;
    }
    
    // Display the blocked URL
    displayBlockedUrl(targetUrl);
    
    if (scanMode) {
        // ⭐ SCANNING MODE: Show scanning UI and perform scan
        showScanningUI();
        performScan(targetUrl);
    } else {
        // WARNING MODE: Show warning for already-scanned malicious site
        updateWarningUI(warningType);
        setupEventListeners(targetUrl);
        setupCountdown();
        logWarningEvent(targetUrl, warningType);
    }
});

// ============================================================================
// SCANNING MODE
// ============================================================================

/**
 * Show scanning UI instead of warning
 */
function showScanningUI() {
    const container = document.querySelector('.container');
    const shieldIcon = container.querySelector('.shield-icon');
    const title = container.querySelector('h1');
    const subtitle = container.querySelector('.warning-subtitle');
    const detailsSection = container.querySelector('.warning-details');
    const checkboxContainer = container.querySelector('.checkbox-container');
    const buttonContainer = container.querySelector('.button-container');
    const countdownEl = document.getElementById('countdown');
    
    // Change shield to blue (scanning)
    shieldIcon.style.background = 'linear-gradient(135deg, #2196F3 0%, #1976D2 100%)';
    shieldIcon.style.boxShadow = '0 10px 30px rgba(33, 150, 243, 0.4)';
    
    // Add spinning animation
    shieldIcon.style.animation = 'spin 2s linear infinite';
    
    // Update text
    title.textContent = '🔍 Scanning Website...';
    title.style.color = '#2196F3';
    
    subtitle.textContent = 'Please wait while we check this site for threats';
    subtitle.style.color = '#64B5F6';
    
    // Hide warning details
    detailsSection.style.display = 'none';
    checkboxContainer.style.display = 'none';
    
    // Show only loading message
    buttonContainer.innerHTML = `
        <div style="text-align: center; padding: 20px;">
            <div class="loading-spinner"></div>
            <p style="color: #aaa; margin-top: 15px; font-size: 14px;">
                Analyzing URL for malicious content...<br>
                This may take a few seconds.
            </p>
        </div>
    `;
    
    countdownEl.style.display = 'none';
    
    // Add spinner CSS if not already present
    if (!document.getElementById('spinner-styles')) {
        const style = document.createElement('style');
        style.id = 'spinner-styles';
        style.textContent = `
            .loading-spinner {
                width: 50px;
                height: 50px;
                margin: 0 auto;
                border: 5px solid #333;
                border-top-color: #2196F3;
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }
            
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
        `;
        document.head.appendChild(style);
    }
}

/**
 * Perform the actual scan by calling background script
 */
async function performScan(url) {
    try {
        console.log('LinkShield: Starting scan for:', url);
        
        // Request scan from background script
        const response = await chrome.runtime.sendMessage({
            action: 'scanUrl',
            url: url
        });
        
        console.log('LinkShield: Scan result:', response.result);
        
        // Handle result
        if (response.result === 'safe') {
            // Site is safe - redirect immediately
            showSafeResult(url);
        } else if (response.result === 'malicious') {
            // Site is malicious - show warning
            showMaliciousWarning();
        } else if (response.result === 'nsfw') {
            // Site is NSFW - show NSFW warning
            showNsfwWarning();
        } else if (response.result === 'no-key') {
            // No API key configured
            showNoKeyError();
        } else if (response.result === 'rate-limited') {
            // Rate limit exceeded
            showRateLimitError(url);
        } else {
            // Error or unknown - allow through for better UX
            showErrorResult(url);
        }
        
    } catch (error) {
        console.error('LinkShield: Scan error:', error);
        showErrorResult(url);
    }
}

/**
 * Show safe result and redirect
 */
function showSafeResult(url) {
    const container = document.querySelector('.container');
    const shieldIcon = container.querySelector('.shield-icon');
    const title = container.querySelector('h1');
    const subtitle = container.querySelector('.warning-subtitle');
    const buttonContainer = container.querySelector('.button-container');
    
    // Green checkmark
    shieldIcon.style.background = 'linear-gradient(135deg, #4CAF50 0%, #45a049 100%)';
    shieldIcon.style.boxShadow = '0 10px 30px rgba(76, 175, 80, 0.4)';
    shieldIcon.style.animation = 'none';
    shieldIcon.innerHTML = `
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z" fill="white"/>
        </svg>
    `;
    
    title.textContent = '✓ Site is Safe';
    title.style.color = '#4CAF50';
    
    subtitle.textContent = 'No threats detected. Redirecting...';
    subtitle.style.color = '#66BB6A';
    
    buttonContainer.innerHTML = `
        <p style="color: #aaa; text-align: center;">
            Redirecting to site in <span id="redirectTimer">2</span> seconds...
        </p>
    `;
    
    // Countdown and redirect
    let seconds = 2;
    const timer = setInterval(() => {
        seconds--;
        const timerEl = document.getElementById('redirectTimer');
        if (timerEl) {
            timerEl.textContent = seconds;
        }
        
        if (seconds <= 0) {
            clearInterval(timer);
            
            // Tell background to allow this URL
            chrome.runtime.sendMessage({ 
                action: 'allowOnce', 
                url: url 
            }, () => {
                // Redirect
                window.location.replace(url);
            });
        }
    }, 1000);
}

/**
 * Show malicious warning
 */
function showMaliciousWarning() {
    const params = new URLSearchParams(window.location.search);
    const url = params.get('url');
    
    // Update URL to include type parameter
    const newUrl = new URL(window.location.href);
    newUrl.searchParams.set('type', 'malicious');
    newUrl.searchParams.delete('scan');
    window.history.replaceState({}, '', newUrl);
    
    // Show malicious warning UI
    updateWarningUI('malicious');
    setupEventListeners(url);
    setupCountdown();
    logWarningEvent(url, 'malicious');
    
    // Also log to blocked history
    chrome.storage.local.get(['blockedHistory'], (data) => {
        const history = data.blockedHistory || [];
        history.unshift({
            url: url,
            timestamp: Date.now(),
            type: 'malicious'
        });
        
        if (history.length > 100) {
            history.pop();
        }
        
        chrome.storage.local.set({ blockedHistory: history });
    });
}

/**
 * Show NSFW warning
 */
function showNsfwWarning() {
    const params = new URLSearchParams(window.location.search);
    const url = params.get('url');
    
    // Update URL to include type parameter
    const newUrl = new URL(window.location.href);
    newUrl.searchParams.set('type', 'nsfw');
    newUrl.searchParams.delete('scan');
    window.history.replaceState({}, '', newUrl);
    
    // Show NSFW warning UI
    updateWarningUI('nsfw');
    setupEventListeners(url);
    setupCountdown();
    logWarningEvent(url, 'nsfw');
    
    // Also log to NSFW history
    chrome.storage.local.get(['nsfwHistory'], (data) => {
        const history = data.nsfwHistory || [];
        history.unshift({
            url: url,
            timestamp: Date.now(),
            type: 'nsfw'
        });
        
        if (history.length > 100) {
            history.pop();
        }
        
        chrome.storage.local.set({ nsfwHistory: history });
    });
}

/**
 * Show no API key error
 */
function showNoKeyError() {
    const container = document.querySelector('.container');
    const shieldIcon = container.querySelector('.shield-icon');
    const title = container.querySelector('h1');
    const subtitle = container.querySelector('.warning-subtitle');
    const detailsSection = container.querySelector('.warning-details');
    const checkboxContainer = container.querySelector('.checkbox-container');
    const buttonContainer = container.querySelector('.button-container');
    
    shieldIcon.style.background = 'linear-gradient(135deg, #FF9800 0%, #F57C00 100%)';
    shieldIcon.style.animation = 'none';
    
    title.textContent = '⚠️ API Key Required';
    title.style.color = '#FF9800';
    
    subtitle.textContent = 'LinkShield needs an API key to scan websites';
    subtitle.style.color = '#FFB74D';
    
    detailsSection.style.display = 'none';
    checkboxContainer.style.display = 'none';
    
    buttonContainer.innerHTML = `
        <button class="btn-safe" id="openSettingsBtn">
            <span>Open Settings</span>
        </button>
        <button class="btn-danger" id="continueAnywayBtn">
            <span>Continue Without Protection</span>
        </button>
    `;
    
    document.getElementById('openSettingsBtn').addEventListener('click', () => {
        chrome.runtime.openOptionsPage();
    });
    
    document.getElementById('continueAnywayBtn').addEventListener('click', () => {
        const params = new URLSearchParams(window.location.search);
        const url = params.get('url');
        
        chrome.runtime.sendMessage({ 
            action: 'allowOnce', 
            url: url 
        }, () => {
            window.location.replace(url);
        });
    });
}

/**
 * Show rate limit error
 */
function showRateLimitError(url) {
    const container = document.querySelector('.container');
    const shieldIcon = container.querySelector('.shield-icon');
    const title = container.querySelector('h1');
    const subtitle = container.querySelector('.warning-subtitle');
    const detailsSection = container.querySelector('.warning-details');
    const checkboxContainer = container.querySelector('.checkbox-container');
    const buttonContainer = container.querySelector('.button-container');
    
    shieldIcon.style.background = 'linear-gradient(135deg, #9E9E9E 0%, #757575 100%)';
    shieldIcon.style.animation = 'none';
    
    title.textContent = '⏱️ Rate Limit Reached';
    title.style.color = '#9E9E9E';
    
    subtitle.textContent = 'Too many scans in a short time. Please wait.';
    subtitle.style.color = '#BDBDBD';
    
    detailsSection.innerHTML = `
        <h3>Why was this blocked?</h3>
        <ul>
            <li>You've reached the maximum number of scans per hour (100)</li>
            <li>This limit helps protect the API from abuse</li>
            <li>You can whitelist frequently visited sites to reduce scans</li>
            <li>Wait a few minutes and try again</li>
        </ul>
    `;
    
    checkboxContainer.style.display = 'none';
    
    buttonContainer.innerHTML = `
        <button class="btn-safe" id="goBackBtn">
            <span>← Go Back</span>
        </button>
        <button class="btn-danger" id="proceedBtn">
            <span>Proceed Anyway (Unprotected)</span>
        </button>
    `;
    
    document.getElementById('goBackBtn').addEventListener('click', handleGoBack);
    document.getElementById('proceedBtn').addEventListener('click', () => {
        chrome.runtime.sendMessage({ 
            action: 'allowOnce', 
            url: url 
        }, () => {
            window.location.replace(url);
        });
    });
}

/**
 * Show error result and allow through
 */
function showErrorResult(url) {
    const container = document.querySelector('.container');
    const shieldIcon = container.querySelector('.shield-icon');
    const title = container.querySelector('h1');
    const subtitle = container.querySelector('.warning-subtitle');
    const buttonContainer = container.querySelector('.button-container');
    
    shieldIcon.style.background = 'linear-gradient(135deg, #FF9800 0%, #F57C00 100%)';
    shieldIcon.style.animation = 'none';
    
    title.textContent = '⚠️ Scan Error';
    title.style.color = '#FF9800';
    
    subtitle.textContent = 'Could not scan this site. Allowing by default.';
    subtitle.style.color = '#FFB74D';
    
    buttonContainer.innerHTML = `
        <p style="color: #aaa; text-align: center;">
            Redirecting in <span id="redirectTimer">3</span> seconds...
        </p>
    `;
    
    // Countdown and redirect
    let seconds = 3;
    const timer = setInterval(() => {
        seconds--;
        const timerEl = document.getElementById('redirectTimer');
        if (timerEl) {
            timerEl.textContent = seconds;
        }
        
        if (seconds <= 0) {
            clearInterval(timer);
            
            chrome.runtime.sendMessage({ 
                action: 'allowOnce', 
                url: url 
            }, () => {
                window.location.replace(url);
            });
        }
    }, 1000);
}

// ============================================================================
// UI CUSTOMIZATION
// ============================================================================

/**
 * Update warning page UI based on warning type
 */
function updateWarningUI(type) {
    const container = document.querySelector('.container');
    const title = container.querySelector('h1');
    const subtitle = container.querySelector('.warning-subtitle');
    const detailsTitle = container.querySelector('.warning-details h3');
    const detailsList = container.querySelector('.warning-details ul');
    const shieldIcon = container.querySelector('.shield-icon');
    const detailsSection = container.querySelector('.warning-details');
    const checkboxContainer = container.querySelector('.checkbox-container');
    const buttonContainers = document.querySelectorAll('.button-container');
    const countdownEl = document.getElementById('countdown');
    
    // Make sure elements are visible
    detailsSection.style.display = 'block';
    checkboxContainer.style.display = 'flex';
    if (countdownEl) countdownEl.style.display = 'block';
    
    // Restore proper button HTML (in case we came from scanning mode)
    if (buttonContainers.length >= 1) {
        buttonContainers[0].innerHTML = `
            <button class="btn-safe" id="goBackBtn">
                <span>← Go Back to Safety</span>
            </button>
            <button class="btn-danger" id="continueBtn">
                <span>Continue Anyway (Not Recommended)</span>
            </button>
        `;
    }
    if (buttonContainers.length >= 2) {
        buttonContainers[1].innerHTML = `
            <button class="btn-report" id="reportBtn">Report False Positive</button>
        `;
    }
    
    if (type === 'nsfw') {
        // NSFW Warning styling
        shieldIcon.style.background = 'linear-gradient(135deg, #ff9800 0%, #f57c00 100%)';
        shieldIcon.style.boxShadow = '0 10px 30px rgba(255, 152, 0, 0.4)';
        shieldIcon.style.animation = 'pulse 2s ease-in-out infinite';
        
        title.textContent = '⚠️ NSFW Content Warning';
        title.style.color = '#ff9800';
        
        subtitle.textContent = 'This site may contain adult or NSFW (Not Safe For Work) content';
        subtitle.style.color = '#ffb74d';
        
        detailsTitle.textContent = 'What is NSFW content?';
        
        detailsList.innerHTML = `
            <li>NSFW stands for "Not Safe For Work"</li>
            <li>This site may contain adult, sexual, or explicit content</li>
            <li>The content may be inappropriate for viewing in public or professional settings</li>
            <li>This includes pornographic material, nudity, or graphic imagery</li>
            <li>You must be 18 or older to view such content</li>
        `;
        
        // Update checkbox label
        const checkboxLabel = document.querySelector('.checkbox-container label');
        checkboxLabel.textContent = 'I understand and wish to disable NSFW warnings for this site.';
        
    } else {
        // Malicious site warning (default)
        shieldIcon.style.background = 'linear-gradient(135deg, #ff4444 0%, #cc0000 100%)';
        shieldIcon.style.boxShadow = '0 10px 30px rgba(255, 68, 68, 0.4)';
        shieldIcon.style.animation = 'pulse 2s ease-in-out infinite';
        
        title.textContent = '⚠️ Dangerous Site Detected';
        title.style.color = '#ff4444';
        
        subtitle.textContent = 'LinkShield has identified this site as potentially malicious';
        subtitle.style.color = '#ff6666';
        
        detailsTitle.textContent = 'Why was this blocked?';
        
        detailsList.innerHTML = `
            <li>This site may contain phishing attempts to steal your credentials</li>
            <li>Malware or ransomware may be present</li>
            <li>The site may be impersonating a legitimate service</li>
            <li>Suspicious or fraudulent activity has been detected</li>
        `;
        
        // Update checkbox label
        const checkboxLabel = document.querySelector('.checkbox-container label');
        checkboxLabel.textContent = 'I trust this site. Don\'t warn me again for this URL.';
    }
}

function setupCountdown() {
    let countdownSeconds = 5;
    const continueBtn = document.getElementById('continueBtn');
    const countdownEl = document.getElementById('countdown');

    if (!continueBtn || !countdownEl) return;

    continueBtn.disabled = true;

    const countdownInterval = setInterval(() => {
        if (countdownSeconds > 0) {
            countdownEl.textContent = `You can continue in ${countdownSeconds} seconds...`;
            countdownSeconds--;
        } else {
            countdownEl.textContent = '';
            continueBtn.disabled = false;
            clearInterval(countdownInterval);
        }
    }, 1000);
}

// ============================================================================
// URL DISPLAY
// ============================================================================

/**
 * Display the blocked URL with proper formatting and security
 */
function displayBlockedUrl(url) {
    const urlElement = document.getElementById('blockedUrl');
    
    try {
        const urlObj = new URL(url);
        
        // Create a safer display format
        const displayText = document.createElement('div');
        displayText.textContent = url; // textContent prevents XSS
        
        // Highlight the domain
        const domain = urlObj.hostname;
        const fullText = displayText.textContent;
        const domainIndex = fullText.indexOf(domain);
        
        if (domainIndex !== -1) {
            const before = fullText.substring(0, domainIndex);
            const after = fullText.substring(domainIndex + domain.length);
            
            urlElement.innerHTML = `${escapeHtml(before)}<strong style="color: #ff6666;">${escapeHtml(domain)}</strong>${escapeHtml(after)}`;
        } else {
            urlElement.textContent = url;
        }
        
    } catch (error) {
        console.error("Error parsing URL:", error);
        urlElement.textContent = url;
    }
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

function setupEventListeners(targetUrl) {
    // Go Back button (safe option)
    const goBackBtn = document.getElementById('goBackBtn');
    if (goBackBtn) {
        goBackBtn.addEventListener('click', () => {
            handleGoBack();
        });
    }
    
    // Continue button (dangerous option)
    const continueBtn = document.getElementById('continueBtn');
    if (continueBtn) {
        continueBtn.addEventListener('click', () => {
            handleContinue(targetUrl);
        });
    }
    
    // Report false positive button
    const reportBtn = document.getElementById('reportBtn');
    if (reportBtn) {
        reportBtn.addEventListener('click', () => {
            handleReport(targetUrl);
        });
    }
    
    // Add keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            handleGoBack();
        }
    });
}

// ============================================================================
// BUTTON HANDLERS
// ============================================================================

/**
 * Go back to previous safe page
 */
function handleGoBack() {
    console.log("User chose to go back");
    
    // Get the tab ID from URL parameters
    const params = new URLSearchParams(window.location.search);
    const tabId = params.get('tabId');
    
    if (tabId) {
        // Navigate back in the tab's history (before the warning page was loaded)
        chrome.tabs.get(parseInt(tabId), (tab) => {
            if (chrome.runtime.lastError) {
                console.error("Tab not found, opening new tab");
                chrome.tabs.create({ url: 'https://www.google.com' });
                return;
            }
            
            // Go back in history - this will go to Google search or previous page
            chrome.tabs.goBack(parseInt(tabId), () => {
                if (chrome.runtime.lastError) {
                    // No history available, open Google
                    console.log("No history, navigating to Google");
                    chrome.tabs.update(parseInt(tabId), { url: 'https://www.google.com' });
                }
            });
        });
    } else {
        // Fallback: close tab if no tabId provided
        chrome.tabs.getCurrent((tab) => {
            if (tab && tab.id) {
                chrome.tabs.remove(tab.id);
            } else {
                window.location.replace('https://www.google.com');
            }
        });
    }
}

/**
 * Continue to dangerous site (with optional whitelist)
 */
function handleContinue() {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    if (!targetUrl) return;

    const continueBtn = document.getElementById('continueBtn');
    const whitelistCheck = document.getElementById('whitelistCheck');

    if (continueBtn) {
        continueBtn.disabled = true;
        continueBtn.innerHTML = '<span>Redirecting...</span>';
    }

    // Handle Permanent Whitelist
    if (whitelistCheck?.checked) {
        chrome.storage.local.set({ [targetUrl]: true }, () => {
            console.log("Site whitelisted successfully");
            logWhitelistEvent(targetUrl);
        });
    }

    // Tell background to allow this URL temporarily and redirect
    chrome.runtime.sendMessage({ 
        action: 'allowOnce', 
        url: targetUrl 
    }, (response) => {
        console.log("Background notified, redirecting...");
        // Redirect using window.location.replace (no history entry)
        setTimeout(() => {
            window.location.replace(targetUrl);
        }, 300);
    });
}

/**
 * Report false positive
 */
function handleReport(targetUrl) {
    const reportBtn = document.getElementById('reportBtn');
    const params = new URLSearchParams(window.location.search);
    const warningType = params.get('type') || 'malicious';
    
    reportBtn.disabled = true;
    reportBtn.textContent = 'Sending Report...';
    
    console.log(`User reporting false positive (${warningType}) for:`, targetUrl);
    
    // Send report to storage (backend can collect these)
    chrome.storage.local.get(['falsePositiveReports'], (data) => {
        const reports = data.falsePositiveReports || [];
        reports.push({
            url: targetUrl,
            type: warningType,
            timestamp: Date.now(),
            userAgent: navigator.userAgent
        });
        
        chrome.storage.local.set({ falsePositiveReports: reports }, () => {
            console.log("Report logged successfully");
            
            reportBtn.textContent = '✓ Report Sent';
            reportBtn.style.borderColor = '#4CAF50';
            reportBtn.style.color = '#4CAF50';
            
            // Optional: Send to server
            sendReportToServer(targetUrl, warningType);
        });
    });
}

/**
 * Send report to server (optional)
 */
async function sendReportToServer(url, warningType) {
    try {
        // Get API key
        const apiKey = await new Promise((resolve) => {
            chrome.storage.sync.get(['apiKey'], (data) => {
                resolve(data.apiKey);
            });
        });
        
        if (!apiKey) {
            console.log("No API key, skipping server report");
            return;
        }
        
        // Send report
        await fetch('https://api.linkshieldai.com/report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': apiKey
            },
            body: JSON.stringify({
                url: url,
                type: `false_positive_${warningType}`,
                timestamp: Date.now()
            })
        });
        
        console.log("Report sent to server");
        
    } catch (error) {
        console.error("Error sending report to server:", error);
    }
}

// ============================================================================
// LOGGING
// ============================================================================

/**
 * Log warning event for analytics
 */
function logWarningEvent(url, type = 'malicious') {
    const historyKey = type === 'nsfw' ? 'nsfwWarningHistory' : 'warningHistory';
    
    chrome.storage.local.get([historyKey], (data) => {
        const history = data[historyKey] || [];
        history.unshift({
            url: url,
            timestamp: Date.now(),
            type: type,
            action: 'warned'
        });
        
        // Keep only last 100 warnings
        if (history.length > 100) {
            history.pop();
        }
        
        chrome.storage.local.set({ [historyKey]: history });
    });
}

/**
 * Log whitelist addition
 */
function logWhitelistEvent(url) {
    chrome.storage.local.get(['warningHistory'], (data) => {
        const history = data.warningHistory || [];
        
        // Update the most recent entry
        if (history.length > 0 && history[0].url === url) {
            history[0].action = 'whitelisted';
            chrome.storage.local.set({ warningHistory: history });
        }
    });
}

// ============================================================================
// VALIDATION & SECURITY
// ============================================================================

/**
 * Validate URL format and security
 * SECURITY: Prevents malicious URL injection
 */
function isValidUrl(urlString) {
    try {
        const url = new URL(urlString);
        
        // Must be HTTP or HTTPS
        if (!['http:', 'https:'].includes(url.protocol)) {
            console.error("Invalid protocol:", url.protocol);
            return false;
        }
        
        // Must have a hostname
        if (!url.hostname) {
            console.error("No hostname in URL");
            return false;
        }
        
        // Blacklist certain patterns
        const blacklist = [
            'javascript:',
            'data:',
            'file:',
            'about:',
            'chrome:',
            'chrome-extension:'
        ];
        
        for (const pattern of blacklist) {
            if (urlString.toLowerCase().startsWith(pattern)) {
                console.error("Blacklisted URL pattern:", pattern);
                return false;
            }
        }
        
        return true;
        
    } catch (error) {
        console.error("URL validation error:", error);
        return false;
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Show error page when URL is invalid
 */
function showError() {
    document.querySelector('.container').innerHTML = `
        <div class="shield-icon">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3zm1 14h-2v-2h2v2zm0-4h-2V7h2v5z" fill="white"/>
            </svg>
        </div>
        <h1 style="color: #ff9800;">Error</h1>
        <p style="color: #aaa; margin: 20px 0;">Invalid or missing URL parameter.</p>
        <button class="btn-safe" onclick="chrome.tabs.getCurrent(tab => chrome.tabs.remove(tab.id))">Close Tab</button>
    `;
}
