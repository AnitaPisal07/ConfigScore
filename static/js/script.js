/**
 * ConfigScore — Website Security Scanner
 * Interactive Client-Side JavaScript
 * B.Sc. Computer Science Final-Year Major Project
 */

document.addEventListener('DOMContentLoaded', function () {
    // 1. Mobile Navigation Toggle
    initMobileNav();

    // 2. Scanner Form Sample Chips & Loading Progress
    initScannerForm();

    // 3. Findings Filter Tabs on Results Page
    initFindingsFilter();

    // 4. Multi-Server Code Tabs in Remediation Boxes
    initCodeTabs();

    // 5. Category Filter on Cyber Security Hub
    initCategoryFilter();
});

/**
 * Mobile Navigation Menu Toggle
 */
function initMobileNav() {
    const navToggle = document.getElementById('navToggle');
    const navMenu = document.getElementById('navMenu');

    if (navToggle && navMenu) {
        navToggle.addEventListener('click', function () {
            navMenu.classList.toggle('show');
        });
    }
}

/**
 * Scanner Form Handling & Progress Rotation
 */
function initScannerForm() {
    const scanForm = document.getElementById('scanForm');
    const urlInput = document.getElementById('urlInput');
    const sampleChips = document.querySelectorAll('.sample-chip');
    const scanLoading = document.getElementById('scanLoading');
    const loadingStatus = document.getElementById('loadingStatus');

    // Clicking sample domain chips fills the input field
    sampleChips.forEach(chip => {
        chip.addEventListener('click', function () {
            const url = this.getAttribute('data-url');
            if (urlInput && url) {
                urlInput.value = url;
                urlInput.focus();
            }
        });
    });

    // Form submission animation
    if (scanForm && scanLoading) {
        scanForm.addEventListener('submit', function (e) {
            const urlVal = urlInput.value.trim();
            if (!urlVal) {
                e.preventDefault();
                alert('Please enter a website URL or domain name.');
                return;
            }

            // Show loading animation
            scanLoading.style.display = 'block';

            // Progressive status hints
            const statuses = [
                '1. Resolving hostname & verifying SSRF safety...',
                '2. Negotiating TLS handshake & inspecting certificate...',
                '3. Analyzing HTTP response headers & cookie flags...',
                '4. Resolving DNS CAA records...',
                '5. Synthesizing findings & computing risk score...'
            ];

            let statusIdx = 0;
            const statusInterval = setInterval(function () {
                statusIdx++;
                if (statusIdx < statuses.length && loadingStatus) {
                    loadingStatus.textContent = statuses[statusIdx];
                } else {
                    clearInterval(statusInterval);
                }
            }, 1000);
        });
    }
}

/**
 * Findings Filter Tabs (All, Missing, Warnings, Review, Passed)
 */
function initFindingsFilter() {
    const filterButtons = document.querySelectorAll('#findingFilters .filter-btn');
    const findingCards = document.querySelectorAll('.finding-card');

    if (filterButtons.length > 0 && findingCards.length > 0) {
        filterButtons.forEach(btn => {
            btn.addEventListener('click', function () {
                // Update active button state
                filterButtons.forEach(b => b.classList.remove('active'));
                this.classList.add('active');

                const filterVal = this.getAttribute('data-filter');

                findingCards.forEach(card => {
                    const cardStatus = card.getAttribute('data-status');
                    if (filterVal === 'all' || cardStatus === filterVal) {
                        card.style.display = 'block';
                    } else {
                        card.style.display = 'none';
                    }
                });
            });
        });
    }
}

/**
 * Multi-Server Code Tabs for Technical Remediation Snippets
 */
function initCodeTabs() {
    // Event delegation for tab navigation buttons
    document.addEventListener('click', function (e) {
        if (e.target && e.target.classList.contains('tab-btn')) {
            const btn = e.target;
            const targetId = btn.getAttribute('data-tab');
            const tabsContainer = btn.closest('.code-tabs');

            if (tabsContainer && targetId) {
                // Remove active from all siblings in this container
                tabsContainer.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                tabsContainer.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

                // Set active on clicked button and matching content
                btn.classList.add('active');
                const targetContent = tabsContainer.querySelector('#' + targetId);
                if (targetContent) {
                    targetContent.classList.add('active');
                }
            }
        }
    });
}

/**
 * One-Click Copy for Remediation Code Snippets
 */
function copySnippet(buttonEl) {
    const tabContent = buttonEl.closest('.tab-content');
    if (!tabContent) return;

    const codeEl = tabContent.querySelector('code');
    if (!codeEl) return;

    const codeText = codeEl.innerText;

    navigator.clipboard.writeText(codeText).then(function () {
        const origText = buttonEl.textContent;
        buttonEl.textContent = 'Copied!';
        buttonEl.style.backgroundColor = 'var(--status-pass)';
        buttonEl.style.color = '#ffffff';

        setTimeout(function () {
            buttonEl.textContent = origText;
            buttonEl.style.backgroundColor = '';
            buttonEl.style.color = '';
        }, 1800);
    }).catch(function (err) {
        console.error('Copy failed: ', err);
    });
}

/**
 * Category Filter on Cyber Security Hub Page
 */
function initCategoryFilter() {
    const categoryPills = document.querySelectorAll('#categoryFilters .category-pill');
    const topicCards = document.querySelectorAll('#topicsGrid .topic-card');

    if (categoryPills.length > 0 && topicCards.length > 0) {
        categoryPills.forEach(pill => {
            pill.addEventListener('click', function () {
                categoryPills.forEach(p => p.classList.remove('active'));
                this.classList.add('active');

                const chosenCat = this.getAttribute('data-cat');

                topicCards.forEach(card => {
                    const cardCat = card.getAttribute('data-category');
                    if (chosenCat === 'all' || cardCat === chosenCat) {
                        card.style.display = 'flex';
                    } else {
                        card.style.display = 'none';
                    }
                });
            });
        });
    }
}
