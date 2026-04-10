document.addEventListener('DOMContentLoaded', () => {
    // State
    let currentData = null;
    let currentFilter = 'all';
    let currentVerifiedFilter = 'all';
    let currentSearch = '';
    let livePollingInterval = null;

    // DOM Elements
    const scanSelector = document.getElementById('scan-selector');
    const fileUpload = document.getElementById('file-upload');
    const loadingState = document.getElementById('loading');
    const emptyState = document.getElementById('no-results');
    const findingsContainer = document.getElementById('findings-container');
    const statsSection = document.getElementById('meta-stats');
    const filtersSection = document.getElementById('filters-section');
    const searchInput = document.getElementById('search-input');
    const filterBtns = document.querySelectorAll('.severity-filters .filter-btn');
    const verifiedFilterBtns = document.querySelectorAll('.verified-filters .filter-btn');

    // Modal Elements
    const modal = document.getElementById('detail-modal');
    const closeModalBtn = document.querySelector('.close-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalBadge = document.getElementById('modal-severity-badge');
    const modalBody = document.getElementById('modal-body');

    // Severity Configuration
    const SEVERITY_SCORES = {
        CRITICAL: { min: 90, class: 'crit', color: 'var(--crit-color)' },
        HIGH: { min: 70, max: 89, class: 'high', color: 'var(--high-color)' },
        MEDIUM: { min: 50, max: 69, class: 'med', color: 'var(--med-color)' },
        LOW: { min: 0, max: 49, class: 'low', color: 'var(--low-color)' }
    };

    const SEVERITY_WEIGHTS = {
        "AWS": 100, "GCP": 100, "Azure": 100, "DigitalOcean": 90,
        "Github": 85, "Gitlab": 85, "Bitbucket": 80,
        "Stripe": 90, "Braintree": 85, "Square": 85,
        "Twilio": 75, "SendGrid": 70, "Mailgun": 70,
        "PostgreSQL": 80, "MySQL": 80, "MongoDB": 80, "Redis": 70,
        "PrivateKey": 95, "JWT": 65,
        "GenericApiKey": 50, "HexHighEntropy": 30, "Base64HighEntropy": 30,
    };

    // Initialize
    fetchAvailableScans();

    // Event Listeners
    scanSelector.addEventListener('change', (e) => {
        if (e.target.value) {
            loadScanFromApi(e.target.value);
        }
    });

    fileUpload.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (event) => {
                try {
                    const data = JSON.parse(event.target.result);
                    processScanData(data);
                    // Add to dropdown as "custom upload"
                    const option = document.createElement('option');
                    option.text = `Uploaded: ${file.name}`;
                    option.value = 'custom';
                    option.selected = true;
                    scanSelector.appendChild(option);
                } catch (err) {
                    alert('Error parsing JSON file: ' + err.message);
                }
            };
            reader.readAsText(file);
        }
    });

    liveToggleBtn.addEventListener('click', () => {
        if (livePollingInterval) {
            // Stop polling
            clearInterval(livePollingInterval);
            livePollingInterval = null;
            liveToggleBtn.classList.remove('active-live');
            liveToggleBtn.innerHTML = '<i class="fa-solid fa-tower-broadcast"></i> Live Monitoring';
            liveToggleBtn.style.backgroundColor = '';
            liveToggleBtn.style.color = '';
        } else {
            // Start polling
            liveToggleBtn.classList.add('active-live');
            liveToggleBtn.innerHTML = '<i class="fa-solid fa-circle-stop"></i> Stop Live';
            liveToggleBtn.style.backgroundColor = '#ef4444';
            liveToggleBtn.style.color = 'white';
            
            // Switch option to live_scan.json if it's there
            let hasLiveScan = Array.from(scanSelector.options).some(opt => opt.value === 'live_scan.json');
            if (!hasLiveScan) {
                const opt = document.createElement('option');
                opt.value = 'live_scan.json';
                opt.text = 'live_scan.json (Live)';
                scanSelector.appendChild(opt);
            }
            scanSelector.value = 'live_scan.json';
            
            // Poll immediately and then every 3s
            loadScanFromApi('live_scan.json', true);
            livePollingInterval = setInterval(() => {
                // If the user changed the dropdown while polling, stop polling
                if (scanSelector.value !== 'live_scan.json') {
                    liveToggleBtn.click(); // Stop polling via click
                    return;
                }
                loadScanFromApi('live_scan.json', true);
            }, 3000);
        }
    });

    searchInput.addEventListener('input', (e) => {
        currentSearch = e.target.value.toLowerCase();
        renderFindings();
    });

    filterBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            filterBtns.forEach(b => b.classList.remove('active'));
            e.currentTarget.classList.add('active');
            currentFilter = e.currentTarget.dataset.filter;
            renderFindings();
        });
    });

    verifiedFilterBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            verifiedFilterBtns.forEach(b => b.classList.remove('active'));
            e.currentTarget.classList.add('active');
            currentVerifiedFilter = e.currentTarget.dataset.verified;
            renderFindings();
        });
    });

    closeModalBtn.addEventListener('click', () => {
        modal.style.display = 'none';
    });

    window.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    });

    // API Interactions
    async function fetchAvailableScans() {
        try {
            const response = await fetch('/api/scans');
            if (response.ok) {
                const scans = await response.json();
                
                scanSelector.innerHTML = '';
                
                if (scans.length === 0) {
                    const option = document.createElement('option');
                    option.text = 'No scans found in results/ directory';
                    option.value = '';
                    scanSelector.appendChild(option);
                    loadingState.style.display = 'none';
                    emptyState.style.display = 'flex';
                    emptyState.querySelector('h3').textContent = 'No Scans Available';
                    emptyState.querySelector('p').textContent = 'Run the scanner or upload a JSON file.';
                    return;
                }

                // Add default option
                const defaultOption = document.createElement('option');
                defaultOption.text = '-- Select a scan result --';
                defaultOption.value = '';
                scanSelector.appendChild(defaultOption);

                scans.forEach(scan => {
                    const option = document.createElement('option');
                    option.text = scan;
                    option.value = scan;
                    scanSelector.appendChild(option);
                });

                // Load the first scan automatically if it's the only one, or just wait for selection
                if (scans.length > 0) {
                    scanSelector.value = scans[0];
                    loadScanFromApi(scans[0]);
                }
            } else {
                throw new Error('Failed to fetch scans list');
            }
        } catch (error) {
            console.error('Error fetching scans:', error);
            scanSelector.innerHTML = '<option value="">Error loading scans (Are you running the Python server?)</option>';
            loadingState.style.display = 'none';
        }
    }

    async function loadScanFromApi(filename, isSilent = false) {
        if (!isSilent) showLoading();
        try {
            const response = await fetch(`/api/scan/${encodeURIComponent(filename)}`);
            if (response.ok) {
                const data = await response.json();
                processScanData(data);
            } else {
                throw new Error(`Failed to fetch scan data for ${filename}`);
            }
        } catch (error) {
            console.error('Error loading scan:', error);
            if (!isSilent) {
                alert('Error loading scan data. Check console for details.');
            } else {
                console.log("Waiting for live scan file...");
            }
            if (!isSilent) hideLoading();
        }
    }

    // Data Processing
    function processScanData(data) {
        currentData = data;
        
        // Enrich findings with severity calculation
        if (currentData && currentData.findings) {
            currentData.findings.forEach(finding => {
                const detectorName = finding.DetectorName || finding.detector_name || 'Unknown';
                const score = calculateSeverityScore(detectorName);
                finding._severityScore = score;
                finding._severityLabel = getSeverityLabel(score);
            });
            
            // Sort by severity (highest first)
            currentData.findings.sort((a, b) => b._severityScore - a._severityScore);
        }

        updateStats();
        hideLoading();
        statsSection.style.display = 'grid';
        filtersSection.style.display = 'flex';
        renderFindings();
    }



    function calculateSeverityScore(detector) {
        const lowerDetector = detector.toLowerCase();
        for (const [key, score] of Object.entries(SEVERITY_WEIGHTS)) {
            if (lowerDetector.includes(key.toLowerCase())) {
                return score;
            }
        }
        return 20; // Default
    }

    function getSeverityLabel(score) {
        if (score >= 90) return 'CRITICAL';
        if (score >= 70) return 'HIGH';
        if (score >= 50) return 'MEDIUM';
        return 'LOW';
    }

    function updateStats() {
        if (!currentData || !currentData.meta) return;
        
        const meta = currentData.meta;
        const total = meta.total_repos || 0;
        const scanned = meta.scanned !== undefined ? meta.scanned : null;
        const cloned = meta.cloned !== undefined ? meta.cloned : null;

        if (scanned !== null && meta.status === 'running') {
            document.getElementById('stat-repos').textContent = `${scanned} / ${total}`;
            document.getElementById('stat-repos-label').textContent = `Scanned (Cloned: ${cloned})`;
            document.getElementById('stat-repos-label').style.color = 'var(--accent-primary)';
        } else {
            document.getElementById('stat-repos').textContent = total;
            document.getElementById('stat-repos-label').textContent = 'Repos Scanned';
            document.getElementById('stat-repos-label').style.color = 'var(--text-muted)';
        }
        
        document.getElementById('stat-secrets').textContent = meta.total_secrets || 0;
        
        let cloneW = meta.clone_workers || 0;
        let scanW = meta.scan_workers || 0;
        document.getElementById('stat-workers').textContent = `${cloneW} CF / ${scanW} TF`;
        
        const rawTs = currentData.meta.timestamp || '';
        if (rawTs && rawTs.length === 15) {
            // Format YYYYMMDD_HHMMSS to something readable
            const year = rawTs.substring(0, 4);
            const month = rawTs.substring(4, 6);
            const day = rawTs.substring(6, 8);
            const hour = rawTs.substring(9, 11);
            const min = rawTs.substring(11, 13);
            document.getElementById('stat-date').textContent = `${year}-${month}-${day} ${hour}:${min}`;
        } else {
            document.getElementById('stat-date').textContent = rawTs;
        }

        const elapsed = currentData.meta.elapsed_sec || 0;
        document.getElementById('stat-time').textContent = `${elapsed}s`;
    }

    // Rendering
    function renderFindings() {
        if (!currentData || !currentData.findings || currentData.findings.length === 0) {
            findingsContainer.innerHTML = '';
            emptyState.style.display = 'flex';
            return;
        }

        // Apply filters
        const filteredFindings = currentData.findings.filter(finding => {
            const sevLabel = finding._severityLabel;
            const isVerified = finding.Verified === true;
            
            const matchesSevFilter = currentFilter === 'all' || sevLabel === currentFilter;
            
            let matchesVerFilter = true;
            if (currentVerifiedFilter === 'verified') matchesVerFilter = isVerified;
            if (currentVerifiedFilter === 'unverified') matchesVerFilter = !isVerified;
            
            if (!matchesSevFilter || !matchesVerFilter) return false;
            if (!currentSearch) return true;

            const searchStr = currentSearch.toLowerCase();
            const repo = (finding._repo || '').toLowerCase();
            const detector = (finding.DetectorName || finding.detector_name || '').toLowerCase();
            const file = (finding.SourceMetadata?.Data?.Filesystem?.file || '').toLowerCase();
            
            return repo.includes(searchStr) || detector.includes(searchStr) || file.includes(searchStr);
        });

        if (filteredFindings.length === 0) {
            findingsContainer.innerHTML = '';
            emptyState.style.display = 'flex';
            emptyState.querySelector('p').textContent = 'No results match your current filters.';
            return;
        }

        emptyState.style.display = 'none';
        findingsContainer.innerHTML = '';

        filteredFindings.forEach((finding, index) => {
            const card = createFindingCard(finding, index);
            findingsContainer.appendChild(card);
        });
    }

    function createFindingCard(finding, index) {
        const repo = finding._repo || 'unknown';
        const detector = finding.DetectorName || finding.detector_name || 'Unknown';
        const sevLabel = finding._severityLabel;
        const sevClass = `sev-${sevLabel.toLowerCase()}`;
        const badgeClass = `badge-${sevLabel.toLowerCase()}`;
        
        // Extract file path safely
        let filepath = 'Unknown file';
        const meta = finding.SourceMetadata || {};
        const data = meta.Data || {};
        
        // Try multiple structures
        if (data.Filesystem && data.Filesystem.file) {
            filepath = data.Filesystem.file;
        } else if (data.Git && data.Git.file) {
            filepath = data.Git.file;
        } else {
            // Just scan values for an object containing 'file'
            for (const value of Object.values(data)) {
                if (typeof value === 'object' && value !== null && value.file) {
                    filepath = value.file;
                    break;
                }
            }
        }

        // Extract secret preview (if available/safe)
        const secretRaw = finding.Raw || finding.raw || finding.RawV2 || finding.raw_v2 || '********';
        // Mask it slightly if it's too long
        const secretPreview = secretRaw.length > 20 
            ? secretRaw.substring(0, 8) + '...' + secretRaw.substring(secretRaw.length - 4) 
            : secretRaw;

        const el = document.createElement('div');
        el.className = `finding-card ${sevClass}`;
        
        const isVerified = finding.Verified === true;
        const verificationBadge = isVerified 
            ? `<span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); margin-top: 5px;"><i class="fa-solid fa-check"></i> Valid</span>`
            : `<span class="badge" style="background: rgba(156, 163, 175, 0.15); color: #9ca3af; border: 1px solid rgba(156, 163, 175, 0.3); margin-top: 5px;"><i class="fa-solid fa-xmark"></i> Invalid/Unverified</span>`;

        el.innerHTML = `
            <div class="card-header">
                <div>
                    <h3 class="detector-name"><i class="fa-solid fa-key" style="margin-right: 8px; opacity: 0.7; font-size: 0.9em;"></i>${detector}</h3>
                    <div class="repo-name"><i class="fa-brands fa-github"></i> ${repo}</div>
                </div>
                <div style="display: flex; flex-direction: column; align-items: flex-end;">
                    <span class="badge ${badgeClass}">${sevLabel}</span>
                    ${verificationBadge}
                </div>
            </div>
            <div class="card-body">
                <div class="info-row">
                    <span class="info-label">File Path</span>
                    <span class="info-value" title="${filepath}">${filepath.length > 45 ? '...' + filepath.substring(filepath.length - 45) : filepath}</span>
                </div>
                <!-- Optional secret preview -->
                <div class="info-row" style="margin-top: 5px;">
                    <span class="info-label">Secret Preview</span>
                    <span class="info-value secret-preview">${secretPreview}</span>
                </div>
            </div>
            <div class="card-footer">
                <button class="view-btn" data-index="${currentData.findings.indexOf(finding)}">
                    <i class="fa-solid fa-eye" style="margin-right: 5px;"></i> View Full Details
                </button>
            </div>
        `;

        el.querySelector('.view-btn').addEventListener('click', (e) => {
            const findingIdx = parseInt(e.currentTarget.dataset.index);
            openModal(currentData.findings[findingIdx]);
        });

        return el;
    }

    function openModal(finding) {
        const repo = finding._repo || 'unknown';
        const detector = finding.DetectorName || finding.detector_name || 'Unknown';
        const sevLabel = finding._severityLabel;
        const badgeClass = `badge-${sevLabel.toLowerCase()}`;
        
        modalTitle.textContent = `${detector} in ${repo}`;
        modalBadge.innerHTML = `<span class="badge ${badgeClass}">${sevLabel}</span>`;
        
        // Build detailed view
        let html = '<div class="detail-grid">';
        
        // 1. Basic Info Section
        html += `<div class="detail-section">
            <h4><i class="fa-solid fa-circle-info"></i> Basic Information</h4>
            <div class="detail-row">
                <div class="info-label">Repository</div>
                <div style="font-weight: 600;">${repo}</div>
            </div>
            <div class="detail-row">
                <div class="info-label">Detector Type</div>
                <div style="font-weight: 600;">${detector} (<a href="${finding.DecoderName || '#'}" target="_blank" style="color:var(--accent-primary)">Docs</a>)</div>
            </div>
            <div class="detail-row">
                <div class="info-label">Verified By TruffleHog?</div>
                <div>${finding.Verified ? '<span style="color:#10b981"><i class="fa-solid fa-check"></i> Yes (Active Credential)</span>' : '<span style="color:#a0aec0"><i class="fa-solid fa-xmark"></i> Unverified / Unknown</span>'}</div>
            </div>
            <div class="detail-row" style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.1);">
                <div class="info-label" style="margin-bottom: 0.5rem;">Manual Validation Override</div>
                <div style="display: flex; gap: 0.5rem;">
                    <button class="btn btn-secondary btn-sm" id="mark-valid-btn" style="${finding.Verified === true && finding.ManualOverride ? 'background: rgba(16, 185, 129, 0.2); border-color: #10b981;' : ''}"><i class="fa-solid fa-check"></i> Mark Valid</button>
                    <button class="btn btn-secondary btn-sm" id="mark-invalid-btn" style="${finding.Verified === false && finding.ManualOverride ? 'background: rgba(239, 68, 68, 0.2); border-color: #ef4444;' : ''}"><i class="fa-solid fa-xmark"></i> Mark Invalid</button>
                </div>
            </div>
        </div>`;

        // 2. Location Section
        let filepath = 'Unknown file';
        let line = 'Unknown';
        let commit = 'N/A';
        
        const meta = finding.SourceMetadata || {};
        const data = meta.Data || {};
        
        for (const value of Object.values(data)) {
            if (typeof value === 'object' && value !== null) {
                if (value.file) filepath = value.file;
                if (value.line) line = value.line;
                if (value.commit) commit = value.commit;
            }
        }

        html += `<div class="detail-section">
            <h4><i class="fa-solid fa-location-dot"></i> Location Context</h4>
            <div class="detail-row">
                <div class="info-label">File Path</div>
                <div class="info-value" style="margin-top:0.25rem;">${filepath}</div>
            </div>
            <div class="detail-row">
                <div class="info-label">Line Number</div>
                <div style="font-weight: 600;">${line}</div>
            </div>
            ${commit !== 'N/A' ? `
            <div class="detail-row">
                <div class="info-label">Commit Hash</div>
                <div class="info-value" style="margin-top:0.25rem;display:inline-block;">${commit}</div>
            </div>` : ''}
        </div>`;
        
        html += '</div>';

        // 3. Raw Secret
        const secretRaw = finding.Raw || finding.raw || finding.RawV2 || finding.raw_v2 || '';
        if (secretRaw) {
            html += `
            <div class="detail-section" style="margin-bottom: 2rem;">
                <h4><i class="fa-solid fa-unlock-keyhole"></i> Extracted Secret</h4>
                <div class="info-value" style="color:var(--text-main); font-size: 1rem; padding: 1rem;">${secretRaw}</div>
            </div>`;
        }
        
        // 4. Full JSON dump
        html += `
        <div class="raw-json-container">
            <h4><i class="fa-solid fa-code"></i> Raw Finding Data</h4>
            <div class="raw-json">${JSON.stringify(finding, null, 2)}</div>
        </div>`;

        modalBody.innerHTML = html;
        modal.style.display = 'block';

        // Add event listeners for the manual override buttons
        const findingIdx = currentData.findings.indexOf(finding);
        
        document.getElementById('mark-valid-btn').addEventListener('click', () => {
            updateFindingStatus(findingIdx, true);
        });
        
        document.getElementById('mark-invalid-btn').addEventListener('click', () => {
            updateFindingStatus(findingIdx, false);
        });
    }

    async function updateFindingStatus(findingIdx, isValid) {
        const currentScan = scanSelector.value;
        if (!currentScan || currentScan === 'custom' || currentScan === '') {
            alert("Cannot update status on an uploaded JSON file or empty selection. You must be viewing a saved scan.");
            return;
        }

        try {
            const response = await fetch('/api/update-status', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    filename: currentScan,
                    index: findingIdx,
                    status: isValid
                })
            });

            if (response.ok) {
                // Update local state
                currentData.findings[findingIdx].Verified = isValid;
                currentData.findings[findingIdx].ManualOverride = true;
                
                // Re-render UI
                renderFindings();
                openModal(currentData.findings[findingIdx]); // refresh modal
            } else {
                throw new Error('Server returned an error');
            }
        } catch (error) {
            console.error('Error updating status:', error);
            alert('Failed to update status. Make sure the server is running locally.');
        }
    }

    // Helpers
    function showLoading() {
        loadingState.style.display = 'flex';
        findingsContainer.innerHTML = '';
        emptyState.style.display = 'none';
    }

    function hideLoading() {
        loadingState.style.display = 'none';
    }
});
