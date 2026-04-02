/*******************************
 * Index Filtering Bar
 *******************************/
function openModal(url, size = 'xl') {
    const modalDialog = document.querySelector('#mainModal .modal-dialog');
    modalDialog.classList.remove('modal-sm', 'modal-lg', 'modal-xl');
    if (size) {
        modalDialog.classList.add('modal-' + size);
    }

    fetch(url)
        .then(response => response.text())
        .then(html => {
            const container = document.getElementById('mainModalBody');
            container.innerHTML = html;
            // Execute script if defined in the modal
            container.querySelectorAll('script').forEach(oldScript => {
                const newScript = document.createElement('script');
                if (oldScript.src) {
                    newScript.src = oldScript.src;
                } else {
                    newScript.textContent = oldScript.textContent;
                }
                document.body.appendChild(newScript);
                document.body.removeChild(newScript);
            });
            initTomSelect(container);
            initCollectionForm(container); //Not really great, temp solution
            let modal = new bootstrap.Modal(document.getElementById('mainModal'));
            modal.show();
        });
}

function multiSelectItems(url) {
    if (selectedItems.size === 0) {
        return;
    }
    const ids = Array.from(selectedItems.keys());
    const fullUrl = url + '/' + JSON.stringify(ids);
    openModal(fullUrl, 'sm');
}

function multiSelectItems2(url) {
    if (selectedItems.size === 0) {
        return;
    }
    const ids = Array.from(selectedItems.keys());
    const fullUrl = url + '/' + JSON.stringify(ids);
    openModal(fullUrl);
}


function redirectToExportResult() {
    const returnFormat = document.getElementById('EventReturnFormat')?.value;
    let idListStr = document.getElementById('PromptForm')?.dataset.idlist;

    if (!returnFormat) return;

    if (Array.isArray(idListStr)) {
        idListStr = JSON.stringify(idListStr);
    }

    window.location = baseurl + '/events/restSearchExport/' + idListStr + '/' + returnFormat;
}

function toggleAllAttributeCheckboxes() {
    const checked = document.getElementById('select_all').checked;

    const checkboxes = document.querySelectorAll('.item-checkbox');

    checkboxes.forEach(checkbox => {
        checkbox.checked = checked;
        checkbox.dispatchEvent(new Event('change', { bubbles: true }));
    });
}


function isMobile() {
    return window.innerWidth < 768;
}

function setView(view, save = true) {
    const tableView = document.getElementById('tableView');
    const cardView  = document.getElementById('cardView');
    const viewList  = document.getElementById('viewList');
    const viewCard  = document.getElementById('viewCard');
    if (view === 'card') {
        tableView?.classList.add('d-none');
        cardView?.classList.remove('d-none');
        viewList?.classList.remove('active');
        viewCard?.classList.add('active');
    } else {
        cardView?.classList.add('d-none');
        tableView?.classList.remove('d-none');
        viewCard?.classList.remove('active');
        viewList?.classList.add('active');
    }

    if (save) localStorage.setItem('indexViewMode', view);
}


function updateMultiSelectToolbar() {
    const toolbar        = document.getElementById('multiSelectToolbar');
    const selectedCount  = document.getElementById('selectedCount');
    const deleteButton   = document.getElementById('multi-delete-button');
    const editButton     = document.getElementById('mass-edit-button');
    const tagButton      = document.getElementById('mass-tag-button');
    const localtagButton = document.getElementById('mass-local-tag-button');
    const clusterButton  = document.getElementById('mass-cluster-button');
    const localclusterButton = document.getElementById('mass-local-cluster-button');
    const objectButton   = document.getElementById('mass-object-button');
    const relationshipButton = document.getElementById('mass-relationship-button');
    const sightingButton = document.getElementById('mass-sighting-button');
    const enableButton   = document.getElementById('mass-enable-button');
    const disableButton  = document.getElementById('mass-disable-button');

    const count          = selectedItems.size;

    if (count === 0) {
        toolbar?.classList.add('d-none');
        return;
    }

    toolbar?.classList.remove('d-none');
    if (selectedCount) selectedCount.textContent = count;

    let canDeleteAll = true;
    let allEnabled = true;
    let allDisabled = true;

    selectedItems.forEach(item => {
        if (!item.canDelete) canDeleteAll = false;
        if (item.state === '1') allDisabled = false;
        if (item.state === '0') allEnabled = false;
    });

    const isHidden = !canDeleteAll;

    deleteButton?.classList.toggle('d-none', isHidden);
    editButton?.classList.toggle('d-none', isHidden);
    tagButton?.classList.toggle('d-none', isHidden);
    localtagButton?.classList.toggle('d-none', isHidden);
    clusterButton?.classList.toggle('d-none', isHidden);
    localclusterButton?.classList.toggle('d-none', isHidden);
    objectButton?.classList.toggle('d-none', isHidden);
    relationshipButton?.classList.toggle('d-none', isHidden);
    sightingButton?.classList.toggle('d-none', isHidden);

    // Specific logic for the Enable/Disable buttons
    if (enableButton && disableButton) {
        if (allDisabled) {
            enableButton.classList.remove('d-none');
            disableButton.classList.add('d-none');
        } else if (allEnabled) {
            enableButton.classList.add('d-none');
            disableButton.classList.remove('d-none');
        } else {
            enableButton.classList.remove('d-none');
            disableButton.classList.remove('d-none');
        }
    }
}




function buildFilterUrl() {
    const base = baseIndexUrl.replace(/\/search.*/, '');
    let filters = {};

    const searchMatch = window.location.pathname.match(/\/search(.+)/);
    if (searchMatch) {
        const parts = searchMatch[1].split('/search');
        parts.forEach(part => {
            const [key, value] = part.split(':');
            if (key && value) filters[key] = decodeURIComponent(value);
        });
    }

    const filterField = document.getElementById('filterField');
    const quickValue = filterField ? filterField.value.trim() : '';

    if (filterBarConfig.mode === 'legacy' || filterBarConfig.mode === 'event') {
        delete filters[filterBarConfig.searchField];
        if (filterBarConfig.idField) delete filters[filterBarConfig.idField];

        if (quickValue !== '') {
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
            const numberRegex = /^[0-9]+$/;

            if (filterBarConfig.idField && (uuidRegex.test(quickValue) || numberRegex.test(quickValue))) {
                filters[filterBarConfig.idField] = encodeURIComponent(quickValue);
            } else {
                filters[filterBarConfig.searchField] = encodeURIComponent(quickValue);
            }
        }
    } else {
        delete filters['quickFilter'];
        if (quickValue !== '') {
            filters['quickFilter'] = encodeURIComponent(quickValue);
        }
    }

    document.querySelectorAll('.topbar-filter').forEach(el => {
        const name  = el.getAttribute('name');
        const value = el.value;
        if (!name) return;
        if (value !== '') filters[name] = value;
        else delete filters[name];
    });

    let newUrl = base;
    if (filterBarConfig.mode === 'event') {
        Object.keys(filters).forEach(key => {
            newUrl += '/search' + key + ':' + filters[key];
        });
    } else {
        Object.keys(filters).forEach(key => {
            newUrl += '/' + key + ':' + filters[key];
        });
    }

    return newUrl;
}

// Listener for non-ajax index
document.addEventListener('DOMContentLoaded', () => {
    // View Mode Toggle
    document.getElementById('viewList')?.addEventListener('click', () => setView('table'));
    document.getElementById('viewCard')?.addEventListener('click', () => setView('card'));

    const savedView = localStorage.getItem('indexViewMode');
    setView(savedView ? savedView : (isMobile() ? 'card' : 'table'), false);


    // Filtering calls
    document.getElementById('quickFilterButton')?.addEventListener('click', () => {
        window.location.href = buildFilterUrl();
    });

    document.getElementById('quickFilterField')?.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') window.location.href = buildFilterUrl();
    });

    document.querySelectorAll('.topbar-filter').forEach(el => {
        el.addEventListener('change', () => {
            window.location.href = buildFilterUrl();
        });
    });

    // Checkbox handler
    document.addEventListener('change', function(e) {
        if (!e.target.classList.contains('item-checkbox')) return;

        const checkbox = e.target;
        const id       = checkbox.dataset.itemId;
        const canDelete = checkbox.dataset.canDelete == "1";
        const state    = checkbox.dataset.state;

        if (checkbox.checked) {
            selectedItems.set(id, { id, canDelete, state });
        } else {
            selectedItems.delete(id);
        }

        updateMultiSelectToolbar();
    });
});


/*******************************
 * Other
 *******************************/
async function getPopup(id, context, target, admin, popupType) {
    //Fetch DOM element
    const grayOut = document.querySelector("#gray_out");
    const loadingIcons = document.querySelectorAll(".loading");
    // Default popup type 
    if (!popupType) popupType = '#popover_form';
    const popupElement = document.querySelector(popupType);

    if (grayOut) {
        grayOut.style.display = "block";
        grayOut.style.opacity = "1";
    }
    //BUILD URL 
    let url = baseurl;
    if (admin) url += "/admin";
    if (context) url += "/" + context;
    if (target) url += "/" + target;
    if (id) url += "/" + id;

    loadingIcons.forEach(el => el.style.display = "block");

    try {
        const response = await fetch(url, {
            method: 'GET',
            cache: 'no-cache'
        });

        if (!response.ok) throw response;

        const data = await response.text();
        loadingIcons.forEach(el => el.style.display = "none");
        if (popupElement) {
            popupElement.innerHTML = data;
            //Need to rewrite openPopup
            openPopup(popupType, false);
        }
    } catch (error) {
        //Handling error by calling error callback
        loadingIcons.forEach(el => el.style.display = "none");
        if (grayOut) grayOut.style.display = "none";
        if (typeof xhrFailCallback === "function") {
            xhrFailCallback(error);
        }
    }
}



function publishPopup(id, type, scope) {
    scope = scope === undefined ? 'events' : scope;
    let action = "alert";

    if (type === "publish") action = "publish";
    else if (type === "unpublish") action = "unpublish";
    else if (type === "sighting") action = "publishSightings";

    fetch(`${baseurl}/${scope}/${action}/${id}`)
        .then(response => {
            if (!response.ok) throw response;
            return response.json();
        })
        .then(data => openConfirmation(data))
        .catch(error => {
            if (typeof xhrFailCallback === 'function') xhrFailCallback(error);
        });
}


function openConfirmation(data) {
    const box = document.getElementById("confirmation_box");
    if (box) {
        box.innerHTML = data;
        openPopup(box);
    }
}


function openPopup(id, adjust_layout = true, callback) {
    const el = (typeof id === 'string') ? document.querySelector(id) : id;
    const grayOut = document.getElementById("gray_out");

    if (!el) return;

    if (adjust_layout) {
        el.style.top = '';
        el.style.height = '';
        el.classList.remove('vertical-scroll');

        const windowHeight = window.innerHeight;
        const popupHeight = el.offsetHeight;

        if (windowHeight < popupHeight) {
            el.style.top = "50px";
            el.style.height = (windowHeight - 50) + "px";
            el.classList.add('vertical-scroll');
        } else {
            let topOffset;
            if (windowHeight > (300 + popupHeight)) {
                topOffset = ((windowHeight - popupHeight) / 2) - 125;
            } else {
                topOffset = (windowHeight - popupHeight) / 2;
            }
            el.style.top = topOffset + "px";
        }
    }

    if (grayOut) {
        grayOut.style.display = 'block';
        grayOut.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 400 });
    }

    el.style.display = 'block';
    const animation = el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 400 });

    animation.onfinish = () => {
        if (typeof callback === 'function') {
            callback();
        }
    };
}

function initTomSelect(container) {
    container.querySelectorAll('.tom-select').forEach(el => {
        if (el.tomselect) return;

        const config = {
            create: false,
            persist: false,
            placeholder: el.dataset.placeholder || 'Select options...'
        };

        if (el.hasAttribute('multiple')) {
            config.plugins = ['remove_button'];
        }

        new TomSelect(el, config);
    });
}


function initCollectionForm(container) {

    const distributionSelect = container.querySelector('#distribution-select');
    const sgContainer = container.querySelector('#sg-container');

    if (!distributionSelect || !sgContainer) return;

    function toggleSharingGroup() {
        if (parseInt(distributionSelect.value) === 4) {
            sgContainer.classList.remove('d-none');
        } else {
            sgContainer.classList.add('d-none');
        }
    }

    toggleSharingGroup();

    distributionSelect.addEventListener('change', toggleSharingGroup);
}



/**
 * Displays a success or error message
 * @param {string} success - 'success' or 'error' (used for the element ID)
 * @param {string} message - The message text
 * @param {string} fullError - Error details for the popover
 */
function showMessage(success, message, fullError) {
    let duration = 1000 + (message.length * 40);
    const contentId = `ajax_${success}`;
    const containerId = `ajax_${success}_container`;

    const contentElem = document.getElementById(contentId);
    const containerElem = document.getElementById(containerId);

    if (!contentElem || !containerElem) return;

    if (message.indexOf("$flashErrorMessage") >= 0) {
        const flashMessageLink = `<a href="#" class="bold" data-content="${escapeHtml(fullError)}" data-html="true" onclick="event.preventDefault(); bootstrap.Popover.getOrCreateInstance(this).show();">here</a>`;
        message = message.replace("$flashErrorMessage", flashMessageLink);
        duration = 5000;
    }

    contentElem.innerHTML = message;

    containerElem.style.display = 'block';

    const fadeIn = containerElem.animate([{ opacity: 0 }, { opacity: 1 }], {
        duration: 600,
        fill: 'forwards'
    });

    fadeIn.onfinish = () => {
        setTimeout(() => {
            const fadeOut = containerElem.animate([{ opacity: 1 }, { opacity: 0 }], {
                duration: 600,
                fill: 'forwards'
            });

            fadeOut.onfinish = () => {
                containerElem.style.display = 'none';
            };
        }, duration);
    };
}


function escapeHtml(unsafe) {
    if (typeof unsafe === "boolean" || typeof unsafe === "number") {
        return unsafe;
    }
    if (!unsafe) return "";

    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };

    return unsafe.replace(/[&<>"']/g, (m) => map[m]);
}




function getCsrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)csrfToken=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : '';
}