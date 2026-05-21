/**
 * LinkShield Options Page
 * Manages all extension settings and configurations
 */

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
    console.log("LinkShield Options: Initializing...");
    
    // Set up tab navigation
    setupTabs();
    
    // Load all settings
    await loadAllSettings();
    
    // Set up event listeners
    setupEventListeners();
    
    // Load statistics
    await updateStatistics();
    
    // Load whitelist
    await loadWhitelist();
    
    // Set version number
    const manifest = chrome.runtime.getManifest();
    document.getElementById('versionNumber').textContent = manifest.version;
});

// ============================================================================
// TAB NAVIGATION
// ============================================================================

function setupTabs() {
    const tabs = document.querySelectorAll('.tab');
    const contents = document.querySelectorAll('.tab-content');
    
    console.log('LinkShield Options: Setting up tabs...');
    console.log(`Found ${tabs.length} tab buttons and ${contents.length} tab contents`);
    
    if (tabs.length === 0 || contents.length === 0) {
        console.error('LinkShield Options: ERROR - Tabs or contents not found!');
        return;
    }
    
    tabs.forEach((tab, index) => {
        console.log(`Tab ${index}: ${tab.textContent.trim()} (data-tab="${tab.dataset.tab}")`);
        
        tab.addEventListener('click', function() {
            const targetTab = this.dataset.tab;
            console.log(`LinkShield Options: Tab clicked - "${targetTab}"`);
            
            // Update tab buttons
            tabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            
            // Update content
            let foundContent = false;
            contents.forEach(content => {
                if (content.dataset.content === targetTab) {
                    content.classList.add('active');
                    foundContent = true;
                    console.log(`LinkShield Options: Showing content for "${targetTab}"`);
                } else {
                    content.classList.remove('active');
                }
            });
            
            if (!foundContent) {
                console.error(`LinkShield Options: ERROR - No content found for tab "${targetTab}"`);
            }
        });
    });
    
    console.log('LinkShield Options: Tab setup complete!');
}

// ============================================================================
// SETTINGS LOADING
// ============================================================================

async function loadAllSettings() {
    // Load API key
    chrome.storage.sync.get(['apiKey'], (data) => {
        if (data.apiKey) {
            document.getElementById('apiKeyInput').value = data.apiKey;
        }
    });
    
    // Load toggles
    chrome.storage.sync.get([
        'enableProtection',
        'showNotifications',
        'skipSafeSites',
        'nsfwProtection'
    ], (data) => {
        document.getElementById('enableProtection').checked = data.enableProtection !== false;
        document.getElementById('showNotifications').checked = data.showNotifications !== false;
        document.getElementById('skipSafeSites').checked = data.skipSafeSites !== false;
        document.getElementById('nsfwProtection').checked = data.nsfwProtection === true;
    });
    
    // Load advanced settings
    chrome.storage.sync.get([
        'cacheDuration',
        'scanTimeout'
    ], (data) => {
        document.getElementById('cacheDuration').value = data.cacheDuration || 24;
        document.getElementById('scanTimeout').value = data.scanTimeout || 5;
    });
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

function setupEventListeners() {
    // API Key management
    document.getElementById('saveApiKeyBtn').addEventListener('click', handleSaveApiKey);
    document.getElementById('testApiKeyBtn').addEventListener('click', handleTestApiKey);
    
    // Protection toggles
    document.getElementById('enableProtection').addEventListener('change', handleToggleChange);
    document.getElementById('showNotifications').addEventListener('change', handleToggleChange);
    document.getElementById('skipSafeSites').addEventListener('change', handleToggleChange);
    document.getElementById('nsfwProtection').addEventListener('change', handleToggleChange);
    
    // Advanced settings
    document.getElementById('saveAdvancedBtn').addEventListener('click', handleSaveAdvanced);
    
    // Data management
    document.getElementById('clearCacheBtn').addEventListener('click', handleClearCache);
    document.getElementById('clearStatsBtn').addEventListener('click', handleClearStats);
    document.getElementById('clearWhitelistBtn').addEventListener('click', handleClearWhitelist);
    document.getElementById('exportDataBtn').addEventListener('click', handleExportData);
    document.getElementById('resetAllBtn').addEventListener('click', handleResetAll);
}

// ============================================================================
// API KEY HANDLERS
// ============================================================================

async function handleSaveApiKey() {
    const btn = document.getElementById('saveApiKeyBtn');
    const apiKey = document.getElementById('apiKeyInput').value.trim();
    
    if (!apiKey) {
        showAlert('Please enter an API key', 'warning');
        return;
    }
    
    btn.disabled = true;
    btn.textContent = 'Validating...';
    
    try {
        // Validate with server
        const isValid = await validateApiKey(apiKey);
        
        if (isValid) {
            // Save to storage
            await new Promise(resolve => {
                chrome.storage.sync.set({ apiKey: apiKey }, resolve);
            });
            
            showAlert('API key saved and validated successfully!', 'success');
            
        } else {
            showAlert('Invalid API key. Please check and try again.', 'warning');
        }
        
    } catch (error) {
        console.error('Error saving API key:', error);
        showAlert('Error validating API key. Please try again.', 'warning');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Save API Key';
    }
}

async function handleTestApiKey() {
    const btn = document.getElementById('testApiKeyBtn');
    const apiKey = document.getElementById('apiKeyInput').value.trim();
    
    if (!apiKey) {
        showAlert('Please enter an API key first', 'warning');
        return;
    }
    
    btn.disabled = true;
    btn.textContent = 'Testing...';
    
    try {
        const isValid = await validateApiKey(apiKey);
        
        if (isValid) {
            showAlert('✓ Connection successful! API key is valid.', 'success');
        } else {
            showAlert('✗ Connection failed. API key is invalid.', 'warning');
        }
        
    } catch (error) {
        showAlert('✗ Connection failed. Please check your internet connection.', 'warning');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Test Connection';
    }
}

async function validateApiKey(apiKey) {
    const response = await chrome.runtime.sendMessage({
        action: 'validateApiKey',
        apiKey: apiKey
    });
    
    return response && response.valid;
}

// ============================================================================
// TOGGLE HANDLERS
// ============================================================================

function handleToggleChange(event) {
    const setting = event.target.id;
    const value = event.target.checked;
    
    chrome.storage.sync.set({ [setting]: value }, () => {
        console.log(`Setting ${setting} = ${value}`);
        showAlert(`Setting updated: ${getSettingLabel(setting)}`, 'info');
    });
}

function getSettingLabel(settingId) {
    const labels = {
        'enableProtection': 'Real-Time Protection',
        'showNotifications': 'Notifications',
        'skipSafeSites': 'Skip Safe Sites',
        'nsfwProtection': 'NSFW Content Protection'
    };
    return labels[settingId] || settingId;
}

// ============================================================================
// ADVANCED SETTINGS
// ============================================================================

function handleSaveAdvanced() {
    const cacheDuration = parseInt(document.getElementById('cacheDuration').value);
    const scanTimeout = parseInt(document.getElementById('scanTimeout').value);
    
    // Validate ranges
    if (cacheDuration < 1 || cacheDuration > 168) {
        showAlert('Cache duration must be between 1 and 168 hours', 'warning');
        return;
    }
    
    if (scanTimeout < 1 || scanTimeout > 30) {
        showAlert('Scan timeout must be between 1 and 30 seconds', 'warning');
        return;
    }
    
    chrome.storage.sync.set({
        cacheDuration: cacheDuration,
        scanTimeout: scanTimeout
    }, () => {
        showAlert('Advanced settings saved successfully!', 'success');
    });
}

// ============================================================================
// STATISTICS
// ============================================================================

async function updateStatistics() {
    try {
        // Get stats from background
        const stats = await chrome.runtime.sendMessage({ action: 'getStats' });
        
        if (stats) {
            document.getElementById('totalScans').textContent = stats.requestsInWindow || 0;
            document.getElementById('cacheSize').textContent = stats.cacheSize || 0;
        }
        
        // Get blocked count
        chrome.storage.local.get(['blockedHistory'], (data) => {
            const history = data.blockedHistory || [];
            document.getElementById('threatsBlocked').textContent = history.length;
        });
        
    } catch (error) {
        console.error('Error updating statistics:', error);
    }
}

function handleClearStats() {
    if (!confirm('Are you sure you want to clear all statistics? This cannot be undone.')) {
        return;
    }
    
    chrome.storage.local.set({
        blockedHistory: [],
        warningHistory: []
    }, () => {
        showAlert('Statistics cleared successfully!', 'success');
        updateStatistics();
    });
}

// ============================================================================
// WHITELIST MANAGEMENT
// ============================================================================

async function loadWhitelist() {
    chrome.storage.local.get(null, (data) => {
        const whitelist = [];
        
        // Find all whitelisted URLs (stored as { url: true })
        for (const [key, value] of Object.entries(data)) {
            if (value === true && key.startsWith('http')) {
                whitelist.push(key);
            }
        }
        
        displayWhitelist(whitelist);
    });
}

function displayWhitelist(urls) {
    const container = document.getElementById('whitelistContainer');
    
    if (urls.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">🛡️</div>
                <p>No trusted sites yet</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = urls.map(url => `
        <div class="whitelist-item">
            <div class="whitelist-url" title="${escapeHtml(url)}">${escapeHtml(url)}</div>
            <button class="whitelist-remove" data-url="${escapeHtml(url)}">Remove</button>
        </div>
    `).join('');
    
    // Add remove event listeners
    container.querySelectorAll('.whitelist-remove').forEach(btn => {
        btn.addEventListener('click', () => {
            const url = btn.dataset.url;
            removeFromWhitelist(url);
        });
    });
}

function removeFromWhitelist(url) {
    chrome.storage.local.remove([url], () => {
        showAlert('Site removed from trusted list', 'success');
        loadWhitelist();
    });
}

function handleClearWhitelist() {
    if (!confirm('Are you sure you want to remove ALL trusted sites? This cannot be undone.')) {
        return;
    }
    
    chrome.storage.local.get(null, (data) => {
        const keysToRemove = [];
        
        // Find all whitelisted URLs
        for (const [key, value] of Object.entries(data)) {
            if (value === true && key.startsWith('http')) {
                keysToRemove.push(key);
            }
        }
        
        if (keysToRemove.length === 0) {
            showAlert('No trusted sites to remove', 'info');
            return;
        }
        
        chrome.storage.local.remove(keysToRemove, () => {
            showAlert(`Removed ${keysToRemove.length} trusted sites`, 'success');
            loadWhitelist();
        });
    });
}

// ============================================================================
// DATA MANAGEMENT
// ============================================================================

async function handleClearCache() {
    const btn = document.getElementById('clearCacheBtn');
    btn.disabled = true;
    btn.textContent = 'Clearing...';
    
    try {
        await chrome.runtime.sendMessage({ action: 'clearCache' });
        showAlert('Cache cleared successfully!', 'success');
        updateStatistics();
    } catch (error) {
        showAlert('Error clearing cache', 'warning');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Clear Cache';
    }
}

function handleExportData() {
    chrome.storage.local.get(null, (localData) => {
        chrome.storage.sync.get(null, (syncData) => {
            const exportData = {
                timestamp: new Date().toISOString(),
                version: chrome.runtime.getManifest().version,
                settings: syncData,
                data: {
                    blockedHistory: localData.blockedHistory || [],
                    warningHistory: localData.warningHistory || [],
                    whitelist: Object.keys(localData).filter(key => 
                        localData[key] === true && key.startsWith('http')
                    )
                }
            };
            
            // Create download
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { 
                type: 'application/json' 
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `linkshield-export-${Date.now()}.json`;
            a.click();
            
            showAlert('Data exported successfully!', 'success');
        });
    });
}

function handleResetAll() {
    const confirmed = confirm(
        'Are you sure you want to reset ALL settings and data?\n\n' +
        'This will:\n' +
        '- Remove your API key\n' +
        '- Clear all statistics\n' +
        '- Remove all trusted sites\n' +
        '- Reset all settings to defaults\n\n' +
        'This cannot be undone!'
    );
    
    if (!confirmed) return;
    
    // Clear all storage
    chrome.storage.local.clear(() => {
        chrome.storage.sync.clear(() => {
            showAlert('All settings and data have been reset', 'success');
            
            // Reload page after 2 seconds
            setTimeout(() => {
                location.reload();
            }, 2000);
        });
    });
}

// ============================================================================
// UI HELPERS
// ============================================================================

function showAlert(message, type) {
    const alertBox = document.getElementById('alertBox');
    alertBox.textContent = message;
    alertBox.className = `alert alert-${type} show`;
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        alertBox.className = 'alert';
    }, 5000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// AUTO-REFRESH
// ============================================================================

// Refresh statistics periodically
setInterval(updateStatistics, 10000); // Every 10 seconds
