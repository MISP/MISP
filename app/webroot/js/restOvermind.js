////////////////////////////////////////////////////////////
/// REST Client - JavaScript for Overmind Theme ///
//////////////////////////////////////////////////////////



// Global variables
let hoverTimeout = null;
let isHoveringCard = false;
let isHoveringTooltip = false;
let bookmarkModalInstance = null;



// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    const bookmarkModalEl = document.getElementById('bookmarkModal');
    if (bookmarkModalEl) {
        bookmarkModalInstance = new bootstrap.Modal(bookmarkModalEl);
    }

    populateRestHistory('bookmark');
    populateRestHistory('history');

    // Keep the tooltip open while the pointer is inside it, so the user can
    // read (and select) a long API description without it slipping away.
    const tooltip = document.getElementById('api-tooltip');
    if (tooltip) {
        tooltip.addEventListener('mouseenter', () => {
            isHoveringTooltip = true;
            clearTimeout(hoverTimeout);
        });
        tooltip.addEventListener('mouseleave', () => {
            isHoveringTooltip = false;
            scheduleHideTooltip();
        });
    }
});



// Functions
function extractPathFromUrl(url) {
    var el = document.createElement('a')
    el.href = url
    return el.pathname
}



function downloadResponse(btn) {
    const text = document.getElementById("response-body-code").innerText;
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "response.json";
    a.click();
    URL.revokeObjectURL(url);

    const originalHtml = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-check text-primary"></i>';
    const tooltip = bootstrap.Tooltip.getInstance(btn);
    if (tooltip) {
        btn.setAttribute('data-bs-original-title', 'Downloaded!');
        tooltip.show();
    }
    setTimeout(() => {
        btn.innerHTML = originalHtml;
        if (tooltip) {
            btn.setAttribute('data-bs-original-title', 'Download Response');
            tooltip.hide();
        }
    }, 2000);
}



function addHeaderRow() {
    const table = document.getElementById("headers-table");
    const row = document.createElement("tr");

    row.innerHTML = `
    <td><input type="text" class="form-control header-key"></td>
    <td><input type="text" class="form-control header-value"></td>
    <td>
        <button class="btn btn-sm btn-outline-danger shadow-none" type="button" onclick="this.closest('tr').remove()">
            <i class="fas fa-times"></i>
        </button>
    </td>
    `;
    table.appendChild(row);
}

async function populateRestHistory(scopeType) {
    const scope = (scopeType === 'history') ? '' : '1';
    const containerSelector = (scopeType === 'history') ? '#history-container' : '#bookmarks-container';
    const container = document.querySelector(containerSelector);

    if (!container) return;

    try {
        const response = await fetch(`${baseurl}/rest_client_history/index/${scope}`, {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        if (response.ok) {
            container.innerHTML = await response.text();
        }
    } catch (error) {
        console.error(`Error loading ${scopeType}:`, error);
    }
}


async function removeRestClientHistoryItem(id, btnElement = null) {
    if (!confirm('Are you sure you want to delete this bookmark?')) return;

    try {
        const response = await fetch(`${baseurl}/rest_client_history/delete/${id}`, {
            method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });

        if (response.ok) {
            if (btnElement) {
                const card = btnElement.closest('.query-card');
                if (card) {
                    card.remove();
                    return;
                }
            }
            populateRestHistory('bookmark');
        }
    } catch (error) {
        console.error('Delete failed:', error);
    }
}


function handleQueryHover(element) {
    isHoveringCard = true;
    clearTimeout(hoverTimeout);

    const url = element.dataset.url;
    if (!url) return;

    hoverTimeout = setTimeout(() => {
        fetchApiInfo(url, element);
    }, 200);
}

function fetchApiInfo(url, element) {
    fetch(baseurl + '/api/getApiInfo', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            url: extractPathFromUrl(url)
        })
    })
    .then(response => response.text())
    .then(data => {
        showApiTooltip(data, element);
    })
    .catch(() => {
        hideApiTooltip();
    });
}


function showApiTooltip(content, element) {
    const tooltip = document.getElementById('api-tooltip');

    tooltip.innerHTML = content;
    tooltip.style.display = 'block';

    const rect = element.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();

    const margin = 8;

    let top = rect.top + window.scrollY - tooltipRect.height - margin;
    let left = rect.left + window.scrollX - tooltipRect.width + rect.width;

    if (left < 8) {
        left = 8;
    }

    if (top < 8) {
        top = rect.bottom + window.scrollY + margin;
    }

    tooltip.style.top = top + 'px';
    tooltip.style.left = left + 'px';
}


function hideApiTooltip() {
    const tooltip = document.getElementById('api-tooltip');
    tooltip.style.display = 'none';
}



function handleInfoHover(iconElement) {
    isHoveringCard = true;
    clearTimeout(hoverTimeout);

    const card = iconElement.closest('.query-card');
    if (!card) return;

    const url = card.dataset.url;
    if (!url) return;

    hoverTimeout = setTimeout(() => {
        fetchApiInfo(url, iconElement);
    }, 200);
}


function showQueryInfo(iconElement) {
    const card = iconElement.closest('.query-card');
    if (!card) return;

    const url = card.dataset.url;
    if (!url) return;

    fetchApiInfo(url, iconElement);
}





function leaveQueryHover() {
    isHoveringCard = false;
    scheduleHideTooltip();
}

function scheduleHideTooltip() {
    clearTimeout(hoverTimeout);

    hoverTimeout = setTimeout(() => {
        if (!isHoveringCard && !isHoveringTooltip) {
            hideApiTooltip();
        }
    }, 150);
}






function syncHeaders() {
    let headerPayload = "";
    const rows = document.querySelectorAll('#headers-table tr');
    rows.forEach(function(row) {
        const keyInput = row.querySelector('.header-key');
        const valInput = row.querySelector('.header-value');
        if (keyInput && valInput && keyInput.value.trim() !== '') {
            headerPayload += keyInput.value.trim() + ': ' + valInput.value.trim() + '\n';
        }
    });
    const hiddenField = document.getElementById('hidden-header-payload');
    if (hiddenField) {
        hiddenField.value = headerPayload.trim();
    }
}



function openBookmarkModal() {
    const method = document.getElementById('server-method').value || 'GET';
    const url = document.getElementById('server-url').value || '/';

    const previewEl = document.getElementById('modal-query-preview');
    previewEl.innerHTML = `<span class="badge bg-secondary me-2">${method}</span> ${url}`;

    document.getElementById('bookmarkNameInput').value = '';

    if (bookmarkModalInstance) {
        bookmarkModalInstance.show();
    }
}

function saveBookmark() {
    const nameInput = document.getElementById('bookmarkNameInput');
    const title = nameInput.value.trim();

    if (!title) {
        nameInput.classList.add('is-invalid');
        return;
    }

    const form = document.getElementById('restClientForm');

    syncHeaders();

    const hiddenName = document.getElementById('hidden-bookmark-name');
    const hiddenBookmark = document.getElementById('hidden-bookmark-checkbox');

    if (hiddenName && hiddenBookmark) {
        hiddenName.value = title;
        hiddenBookmark.checked = true; // On coche la case cachée
    }

    const skipSslCheckbox = document.getElementById('skip-ssl');
    if (skipSslCheckbox) {
        skipSslCheckbox.checked = true;
    }

    bookmarkModalInstance.hide();

    form.submit();
}


async function deleteBookmark(id, cardElement = null) {
    if (!confirm('Are you sure you want to delete this query?')) return;

    try {
        const response = await fetch(`${baseurl}/rest_client_history/delete/${id}`, {
            method: 'POST',
            headers: { 
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json' 
            },
            body: '[]' 
        });

        if (response.ok) {
            if (cardElement) {
                cardElement.remove();
            }

            populateRestHistory('bookmark');
            populateRestHistory('history');

        } else {
            throw new Error('Server returned an error');
        }
    } catch (error) {
        if (typeof handleGenericAjaxResponse === 'function') {
            handleGenericAjaxResponse({
                'saved': false, 
                'errors': ['Request failed due to an unexpected error.']
            });
        } else {
            console.error('Delete failed:', error);
            alert('Request failed due to an unexpected error.');
        }
    }
}






function applyQuery(element) {
    const payloadStr = element.getAttribute('data-payload');
    if (!payloadStr) return;

    let data;
    try {
        data = JSON.parse(payloadStr);
    } catch (e) {
        console.error("Impossible de lire les données du favori", e);
        return;
    }

    const urlInput = document.getElementById('server-url');
    const methodSelect = document.getElementById('server-method');
    if (urlInput) urlInput.value = data['url'] || '';
    if (methodSelect) methodSelect.value = data['http_method'] || 'GET';

    const bodyTextarea = document.getElementById('server-body');
    const descriptionBox = document.getElementById('template_description');
    if (bodyTextarea) {
        bodyTextarea.value = data['body'] || '';
        if (descriptionBox) descriptionBox.style.display = 'none';
    }

    const headersTable = document.getElementById('headers-table');
    if (headersTable) {
        headersTable.innerHTML = '';
        if (data['headers']) {
            const lines = data['headers'].split('\n');
            lines.forEach(line => {
                if (line.trim() === '') return;

                const parts = line.split(':');
                if (parts.length >= 2) {
                    const key = parts.shift().trim();
                    const val = parts.join(':').trim();

                    const row = document.createElement("tr");
                    row.innerHTML = `
                    <td><input type="text" class="form-control header-key" value="${key}"></td>
                    <td><input type="text" class="form-control header-value" value="${val}"></td>
                    <td>
                        <button class="btn btn-sm btn-outline-danger shadow-none" type="button" onclick="this.closest('tr').remove()">
                            <i class="fas fa-times"></i>
                        </button>
                    </td>
                    `;
                    headersTable.appendChild(row);
                }
            });
        }
    }

    const skipSsl = document.getElementById('skip-ssl');
    if (skipSsl) skipSsl.checked = (data['skip_ssl'] == 1 || data['skip_ssl'] === true);

    const showResult = document.getElementById('show-result');
    if (showResult) showResult.checked = (data['show_result'] == 1 || data['show_result'] === true);

    document.getElementById('rest-client-container').scrollIntoView({
        behavior: 'smooth'
    });
}


function applyTemplate(element) {
    const url = element.dataset.url;
    const method = element.dataset.method;

    const urlInput = document.querySelector('input[name="data[Server][url]"]');
    const methodSelect = document.querySelector('select[name="data[Server][method]"]');
    const bodyTextarea = document.querySelector('textarea[name="data[Server][body]"]');
    const descriptionBox = document.getElementById('template_description');

    if (urlInput) urlInput.value = allValidApis[url].url;
    if (methodSelect) methodSelect.value = method;

    if (allValidApis[url] && bodyTextarea) {
        const body = allValidApis[url].body || {};
        const formattedBody = JSON.stringify(body, null, 4);

        const currentBody = bodyTextarea.value.trim();
        const lastTemplate = bodyTextarea.dataset.lastTemplate;

        const shouldReplace =
            currentBody === '' || lastTemplate !== url;

        if (shouldReplace) {
            bodyTextarea.value = formattedBody;
            bodyTextarea.dataset.lastTemplate = url;
        }

        if (descriptionBox) descriptionBox.style.display = 'block';

    } else {
        if (descriptionBox) descriptionBox.style.display = 'none';
    }

    document.getElementById('rest-client-container').scrollIntoView({
        behavior: 'smooth'
    });
}

