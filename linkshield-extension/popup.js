/**
 * LinkShield Popup Interface
 * Handles API key management, statistics, and user interactions
 */

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
    console.log("LinkShield Popup: Initializing...");
    
    // Load and display current state
    await loadApiKey();
    await updateStatistics();
    await updateProtectionStatus();
    
    // Set up event listeners
    setupEventListeners();
    
    // Set version number
    const manifest = chrome.runtime.getManifest();
    document.getElementById('version').textContent = `Version ${manifest.version}`;
});

// ============================================================================
// EVENT LISTENERS
// ============================================================================

function setupEventListeners() {
    // Save API Key button
    document.getElementById('saveBtn').addEventListener('click', handleSaveApiKey);
    
    // Toggle API Key visibility
    document.getElementById('toggleKeyBtn').addEventListener('click', toggleApiKeyVisibility);
    
    // Clear cache button
    document.getElementById('clearCacheBtn').addEventListener('click', handleClearCache);
    
    // API Key input - validate on blur
    document.getElementById('apiKey').addEventListener('blur', validateApiKeyFormat);
    
    // API Key input - clear validation on focus
    document.getElementById('apiKey').addEventListener('focus', () => {
        document.getElementById('apiKey').classList.remove('valid', 'invalid');
        hideValidationMessage();
    });
    
    // Footer links
    document.getElementById('viewHistoryLink').addEventListener('click', (e) => {
        e.preventDefault();
        chrome.runtime.openOptionsPage();
    });
    
    document.getElementById('manageWhitelistLink').addEventListener('click', (e) => {
        e.preventDefault();
        chrome.runtime.openOptionsPage();
    });
    
    document.getElementById('settingsLink').addEventListener('click', (e) => {
        e.preventDefault();
        chrome.runtime.openOptionsPage();
    });
}

// ============================================================================
// API KEY MANAGEMENT
// ============================================================================

/**
 * Load existing API key from storage
 */
async function loadApiKey() {
    return new Promise((resolve) => {
        chrome.storage.sync.get(['apiKey'], (data) => {
            const keyInput = document.getElementById('apiKey');
            if (data.apiKey) {
                keyInput.value = data.apiKey;
                keyInput.classList.add('valid');
            }
            resolve();
        });
    });
}

/**
 * Save and validate API key
 */
async function handleSaveApiKey() {
    const saveBtn = document.getElementById('saveBtn');
    const saveBtnText = document.getElementById('saveBtnText');
    const keyInput = document.getElementById('apiKey');
    const apiKey = keyInput.value.trim();
    
    // Validate format first
    if (!apiKey) {
        showAlert('Please enter an API key', 'warning');
        return;
    }
    
    if (!validateApiKeyFormat()) {
        return;
    }
    
    // Disable button and show loading
    saveBtn.disabled = true;
    saveBtnText.innerHTML = 'Validating <span class="loading"></span>';
    
    try {
        // Validate with server
        const isValid = await validateApiKeyWithServer(apiKey);
        
        if (isValid) {
            // Save to storage
            await new Promise((resolve) => {
                chrome.storage.sync.set({ apiKey: apiKey }, resolve);
            });
            
            // Update UI
            keyInput.classList.remove('invalid');
            keyInput.classList.add('valid');
            showValidationMessage('API key is valid and saved!', 'success');
            showAlert('API key saved successfully! Protection is now active.', 'info');
            
            // Update status
            await updateProtectionStatus();
            
            // Clear any error badges
            chrome.runtime.sendMessage({ action: 'clearBadge' });
            
        } else {
            keyInput.classList.remove('valid');
            keyInput.classList.add('invalid');
            showValidationMessage('Invalid API key. Please check and try again.', 'error');
            showAlert('API key validation failed. Please verify your key.', 'warning');
        }
        
    } catch (error) {
        console.error('Validation error:', error);
        showAlert('Could not validate API key. Please check your internet connection.', 'warning');
    } finally {
        // Re-enable button
        saveBtn.disabled = false;
        saveBtnText.textContent = 'Save & Validate';
    }
}

/**
 * Validate API key format (client-side check)
 */
function validateApiKeyFormat() {
    const keyInput = document.getElementById('apiKey');
    const apiKey = keyInput.value.trim();
    
    // Basic format validation
    // Assuming format: sk_xxxxxxxxxxxxxxxxxxxx (at least 20 chars)
    const isValid = apiKey.length > 2;
    
    if (!isValid && apiKey.length > 0) {
        keyInput.classList.add('invalid');
        showValidationMessage('API key should be at least 3 characters long', 'error');
        return false;
    }
    
    return true;
}

/**
 * Validate API key with server
 */
async function validateApiKeyWithServer(apiKey) {
    try {
        const response = await chrome.runtime.sendMessage({
            action: 'validateApiKey',
            apiKey: apiKey
        });
        
        return response && response.valid;
    } catch (error) {
        console.error('Server validation error:', error);
        return false;
    }
}

/**
 * Toggle API key visibility
 */
function toggleApiKeyVisibility() {
    const keyInput = document.getElementById('apiKey');
    const toggleBtn = document.getElementById('toggleKeyBtn');
    
    if (keyInput.type === 'password') {
        keyInput.type = 'text';
        toggleBtn.textContent = 'Hide API Key';
    } else {
        keyInput.type = 'password';
        toggleBtn.textContent = 'Show API Key';
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * Update statistics display
 */
async function updateStatistics() {
    try {
        // Get stats from background script
        const stats = await chrome.runtime.sendMessage({ action: 'getStats' });
        
        if (stats) {
            document.getElementById('cacheSize').textContent = stats.cacheSize || 0;
            document.getElementById('sitesScanned').textContent = stats.requestsInWindow || 0;
        }
        
        // Get blocked sites count from storage
        chrome.storage.local.get(['blockedHistory'], (data) => {
            const history = data.blockedHistory || [];
            document.getElementById('threatsBlocked').textContent = history.length;
        });
        
    } catch (error) {
        console.error('Error updating statistics:', error);
    }
}

/**
 * Update protection status badge
 */
async function updateProtectionStatus() {
    const statusBadge = document.getElementById('statusBadge');
    
    chrome.storage.sync.get(['apiKey'], (data) => {
        if (data.apiKey && data.apiKey.length > 0) {
            statusBadge.textContent = 'Protected';
            statusBadge.className = 'status-badge status-active';
        } else {
            statusBadge.textContent = 'Not Protected';
            statusBadge.className = 'status-badge status-inactive';
        }
    });
}

// ============================================================================
// CACHE MANAGEMENT
// ============================================================================

/**
 * Clear scan cache
 */
async function handleClearCache() {
    const clearBtn = document.getElementById('clearCacheBtn');
    
    try {
        clearBtn.disabled = true;
        clearBtn.textContent = 'Clearing...';
        
        await chrome.runtime.sendMessage({ action: 'clearCache' });
        
        showAlert('Cache cleared successfully!', 'info');
        await updateStatistics();
        
        clearBtn.textContent = 'Cache Cleared!';
        setTimeout(() => {
            clearBtn.disabled = false;
            clearBtn.textContent = 'Clear Cache';
        }, 2000);
        
    } catch (error) {
        console.error('Error clearing cache:', error);
        clearBtn.disabled = false;
        clearBtn.textContent = 'Clear Cache';
        showAlert('Error clearing cache', 'warning');
    }
}

// ============================================================================
// UI HELPERS
// ============================================================================

/**
 * Show validation message under input
 */
function showValidationMessage(message, type) {
    const msgEl = document.getElementById('validationMsg');
    msgEl.textContent = message;
    msgEl.className = `validation-message show ${type}`;
}

/**
 * Hide validation message
 */
function hideValidationMessage() {
    const msgEl = document.getElementById('validationMsg');
    msgEl.className = 'validation-message';
}

/**
 * Show alert box
 */
function showAlert(message, type) {
    const alertBox = document.getElementById('alertBox');
    alertBox.textContent = message;
    alertBox.className = `alert alert-${type} show`;
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        alertBox.className = 'alert';
    }, 5000);
}

// ============================================================================
// AUTO-REFRESH
// ============================================================================

// Refresh statistics every 5 seconds while popup is open
setInterval(updateStatistics, 5000);
