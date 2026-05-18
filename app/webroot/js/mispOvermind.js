// Initializing Bootstrap 5 tooltips
document.addEventListener('DOMContentLoaded', function() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });
});

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
            container.querySelectorAll('script:not([type="application/json"])').forEach(oldScript => {
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
            initCollectionForm(container);
            initTemplateElementForm(container);
            initServerForm(container);
            initSharingGroupForm(container);

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
    const requireButton   = document.getElementById('mass-require-button');
    const optionalButton  = document.getElementById('mass-optional-button');
    const highlightButton   = document.getElementById('mass-highlight-button');
    const removehighlightButton  = document.getElementById('mass-removehighlight-button');

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
    let allRequired = true;
    let allOptional = true;
    let allHighlighted = true;
    let allRemovehighlighted = true;

    selectedItems.forEach(item => {
        if (!item.canDelete) canDeleteAll = false;
        if (item.enable === '1') allDisabled = false;
        if (item.enable === '0') allEnabled = false;
        if (item.require === '1') allOptional = false;
        if (item.require === '0') allRequired = false;
        if (item.highlight === '1') allRemovehighlighted = false;
        if (item.highlight === '0') allHighlighted = false;
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

    if (requireButton && optionalButton) {
        if (allOptional) {
            requireButton.classList.remove('d-none');
            optionalButton.classList.add('d-none');
        } else if (allRequired) {
            requireButton.classList.add('d-none');
            optionalButton.classList.remove('d-none');
        } else {
            requireButton.classList.remove('d-none');
            optionalButton.classList.remove('d-none');
        }
    }

    if (highlightButton && removehighlightButton) {
        if (allRemovehighlighted) {
            highlightButton.classList.remove('d-none');
            removehighlightButton.classList.add('d-none');
        } else if (allHighlighted) {
            highlightButton.classList.add('d-none');
            removehighlightButton.classList.remove('d-none');
        } else {
            highlightButton.classList.remove('d-none');
            removehighlightButton.classList.remove('d-none');
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

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('viewList')?.addEventListener('click', () => setView('table'));
    document.getElementById('viewCard')?.addEventListener('click', () => setView('card'));

    const savedView = localStorage.getItem('indexViewMode');
    setView(savedView ? savedView : (isMobile() ? 'card' : 'table'), false);

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

    document.addEventListener('change', function(e) {
        if (!e.target.classList.contains('item-checkbox')) return;

        const checkbox = e.target;
        const id       = checkbox.dataset.itemId;
        const canDelete = checkbox.dataset.canDelete == "1";
        const publish    = checkbox.dataset.publish;
        const enable    = checkbox.dataset.enable;
        const require    = checkbox.dataset.require;
        const highlight    = checkbox.dataset.highlight;

        if (checkbox.checked) {
            selectedItems.set(id, { id, canDelete, publish, enable, require, highlight});
        } else {
            selectedItems.delete(id);
        }

        updateMultiSelectToolbar();
    });
});

/*******************************
 * Tags
 *******************************/
function toggleTags(badge) {
    const container = badge.closest('.tag-container');
    const hiddenTags = container.querySelectorAll('.extra-tag');

    if (!hiddenTags.length) return;

    const isHidden = hiddenTags[0].classList.contains('d-none');
    hiddenTags.forEach(g => g.classList.toggle('d-none'));

    badge.textContent = isHidden ? '−' : '+' + hiddenTags.length;
}

document.addEventListener('DOMContentLoaded', function() {
    document.body.addEventListener('click', async function(e) {
        const starIcon = e.target.closest('.tag-star');

        if (starIcon) {
            e.preventDefault();
            e.stopPropagation();

            const tagId = starIcon.getAttribute('data-id');
            const wasFavourite = starIcon.classList.contains('fas');
            starIcon.classList.toggle('fas');
            starIcon.classList.toggle('far');

            const formData = new URLSearchParams();
            formData.append('data[FavouriteTag][data]', tagId);

            try {
                const url = (typeof baseurl !== 'undefined' ? baseurl : '') + '/favourite_tags/toggle';
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept': 'application/json'
                    },
                    body: formData
                });

                const result = await response.json();

                if (!result.saved) {
                    revertStar(starIcon, wasFavourite);
                    console.error('Erreur lors du changement de favori:', result.fails);
                }
            } catch (error) {
                revertStar(starIcon, wasFavourite);
                console.error('Erreur réseau lors de la mise à jour du favori:', error);
            }
        }
    });

    function revertStar(element, shouldBeFavourite) {
        if (shouldBeFavourite) {
            element.classList.add('fas text-warning');
            element.classList.remove('far text-muted');
        } else {
            element.classList.add('far text-muted');
            element.classList.remove('fas text-warning');
        }
    }
});


/*******************************
 * Servers
 *******************************/


function testSyncRule(id, method) {
    function esc(input) {
        return String(input === null || input === undefined ? '' : input)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    var resultContainer = document.getElementById("sync_rule_" + method + "_test_" + id);
    if (!resultContainer) return;

    resultContainer.innerHTML = '<span class="text-muted">' +
        '<i class="fas fa-spinner fa-spin me-1"></i>Running test...' +
        '</span>';

    fetch(baseurl + '/servers/testSyncRules/' + id + '/' + method)
        .then(response => response.json().catch(() => null))
        .then(function(response) {
            resultContainer.innerHTML = '';

            if (typeof response !== 'object' || response === null) {
                resultContainer.innerHTML =
                    '<span class="text-danger fw-semibold">Internal error</span>';
            } else if ("error" in response) {
                resultContainer.innerHTML =
                    '<span class="text-danger fw-semibold">Error: #' +
                    esc(response.error) + '</span>';
            } else {
                var resultTextFiltered = response.without_rules - response.with_rules;
                if (resultTextFiltered !== 0) {
                    resultTextFiltered += ' (' + (((response.without_rules - response.with_rules) / response.without_rules) * 100).toFixed(1) + '%)';
                }

                var resultTextSync = response.with_rules;
                if (resultTextSync !== 0) {
                    resultTextSync += ' (' + ((response.with_rules / response.without_rules) * 100).toFixed(1) + '%)';
                }

                resultContainer.innerHTML =
                    '<div class="border rounded p-2 bg-light">' +
                    '<div class="d-flex justify-content-between gap-2">' +
                    '<span class="text-muted">Dropped Events :</span>' +
                    '<span class="fw-semibold text-danger text-end">' +
                    esc(resultTextFiltered) + '</span></div>' +
                    '<div class="d-flex justify-content-between gap-2">' +
                    '<span class="text-muted">Events to be Synced :</span>' +
                    '<span class="fw-semibold text-success text-end">' +
                    esc(resultTextSync) + '</span></div>' +
                    '</div>';
            }
        })
        .catch(function() {
            resultContainer.innerHTML =
                '<span class="text-danger fw-semibold">Internal error</span>';
        });
}


function testConnection(id) {
    function esc(input) {
        return String(input === null || input === undefined ? '' : input)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    var container = document.getElementById("connection_test_" + id);
    if (!container) return;
    var resultContainer = container.querySelector('.server-action-result') || container;

    resultContainer.innerHTML = '<span class="text-muted">' +
        '<i class="fas fa-spinner fa-spin me-1"></i>Running test...' +
        '</span>';

    fetch(baseurl + '/servers/testConnection/' + id)
        .then(response => response.json())
        .then(function(result) {

            function line(name, value, valid) {
                var badgeClass = 'text-secondary';
                if (valid === true || valid === 'green') {
                    badgeClass = 'text-end text-success';
                } else if (valid === false || valid === 'red') {
                    badgeClass = 'text-end text-danger';
                } else if (valid === 'orange') {
                    badgeClass = 'text-end text-warning';
                }

                var valueText = esc(value || '-');
                return '<div class="d-flex justify-content-between gap-2">' +
                    '<span class="text-muted">' + name + '</span>' +
                    '<span class="fw-semibold ' + badgeClass + '">' +
                    valueText + '</span></div>';
            }

            var html = '';

            if (result.client_certificate) {
                var cert = result.client_certificate;
                html += '<div class="fw-semibold mb-1">Client certificate</div>';
                html += '<div class="border rounded p-2 mb-2 bg-light">';

                if (cert.error) {
                    html += '<div class="text-danger fw-semibold">Error: ' +
                        esc(cert.error) + '</div>';
                } else {
                    html += line("Subject", cert.subject);
                    html += line("Issuer", cert.issuer);
                    html += line("Serial number", cert.serial_number);
                    html += line("Valid from", cert.valid_from, cert.valid_from_ok);
                    html += line("Valid to", cert.valid_to, cert.valid_to_ok);
                    html += line(
                        "Public key",
                        cert.public_key_type + ' (' + cert.public_key_size + ' bits)',
                        cert.public_key_size_ok
                    );
                }
                html += '</div>';
            }

            switch (result.status) {
                case 1:
                    var status_message = "OK";
                    var compatibility = "Compatible";
                    var compatibility_colour = "green";
                    var colours = {local: 'green', remote: 'green', status: 'green'};
                    var issue_colour = "red";

                    if (result.mismatch == "hotfix") issue_colour = "orange";

                    if (result.newer == "local") {
                        colours.remote = issue_colour;

                        if (result.mismatch == "minor") {
                            compatibility = "Pull only";
                            compatibility_colour = "orange";
                        } else if (result.mismatch == "major") {
                            compatibility = "Incompatible";
                            compatibility_colour = "red";
                        } else if (result.mismatch == "minor_compatible") {
                            compatibility_colour = "green";
                        }
                    } else if (result.newer == "remote") {
                        colours.local = issue_colour;

                        if (result.mismatch != "hotfix") {
                            compatibility = "Incompatible";
                            compatibility_colour = "red";
                        }
                    } else if (result.mismatch == "proposal") {
                        compatibility_colour = "orange";
                        compatibility = "Proposal pull disabled (remote version < v2.4.111)";
                    }

                    if (result.mismatch !== false && result.mismatch != "proposal") {
                        if (result.newer == "remote") {
                            status_message = "Local instance outdated, update!";
                        } else if (result.newer == "local") {
                            if (result.mismatch == "minor_compatible") {
                                status_message = "Remote on 2.4, moving to 2.5 is recommended.";
                            } else {
                                status_message = "Remote outdated, notify admin!";
                            }
                        }
                        colours.status = issue_colour;
                    }

                    var post_result = '';
                    if (result.post !== false) {
                        var post_colour = "red";

                        if (result.post == 1) {
                            post_colour = "green";
                            post_result = "Received sent package";
                        } else if (result.post == 8) {
                            post_result = "Could not POST message";
                        } else if (result.post == 9) {
                            post_result = "Invalid body";
                        } else if (result.post == 10) {
                            post_result = "Invalid headers";
                        } else {
                            post_colour = "orange";
                            post_result = "Remote too old for this test";
                        }
                    }

                    html += '<div class="border rounded p-2 bg-light">';
                    html += line('Local version', result.local_version, colours.local);
                    html += line('Remote version', result.version, colours.remote);
                    html += line('Status', status_message, colours.status);
                    html += line('Compatibility', compatibility, compatibility_colour);
                    html += line('POST test', post_result, post_colour);
                    html += '</div>';
                    break;

                case 2:
                    html += '<div class="text-danger fw-semibold">Server unreachable</div>';
                    break;
                case 3:
                    html += '<div class="text-danger fw-semibold">Unexpected error</div>';
                    break;
                case 4:
                    html += '<div class="text-danger fw-semibold">Authentication failed</div>';
                    break;
                case 5:
                    html += '<div class="text-danger fw-semibold">Password change required</div>';
                    break;
                case 6:
                    html += '<div class="text-danger fw-semibold">Terms not accepted</div>';
                    break;
                case 7:
                    html += '<div class="text-warning fw-semibold">Remote user not a sync user</div>';
                    break;
                case 8:
                    html += '<div class="text-warning fw-semibold">Remote user not a sync user (sightings only)</div>';
                    break;
            }

            resultContainer.innerHTML = html;
        })
        .catch(function() {
            resultContainer.innerHTML = '<span class="text-danger fw-semibold">Internal error</span>';
        });
}


function getRemoteSyncUser(id) {
    function esc(input) {
        return String(input === null || input === undefined ? '' : input)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    var container = document.getElementById("sync_user_test_" + id);
    if (!container) return;
    var resultContainer = container.querySelector('.server-action-result') || container;

    fetch(baseurl + '/servers/getRemoteUser/' + id)
        .then(function(response) {
            resultContainer.innerHTML = '<span class="text-muted">' +
                '<i class="fas fa-spinner fa-spin me-1"></i>Running test...' +
                '</span>';
            return response.json().catch(() => null);
        })
        .then(function(response) {
            resultContainer.innerHTML = '';

            if (typeof response !== 'object' || response === null) {
                resultContainer.innerHTML =
                    '<span class="text-danger fw-semibold">Internal error</span>';
            } else if ("error" in response) {
                resultContainer.innerHTML =
                    '<div class="text-danger fw-semibold">Error: #' +
                    esc(response.error) + '</div>';
            } else {
                var wrapper = document.createElement('div');
                wrapper.className = 'border rounded p-2 bg-light';
                Object.keys(response).forEach(function(key) {
                    var value = response[key];
                    var row = document.createElement('div');
                    row.className = 'd-flex justify-content-between gap-2';
                    row.innerHTML = '<span class="text-muted">' + esc(key) + '</span>' +
                        '<span class="fw-semibold">' + esc(value) + '</span>';
                    wrapper.appendChild(row);
                });
                resultContainer.appendChild(wrapper);
            }
        })
        .catch(function() {
            resultContainer.innerHTML =
                '<span class="text-danger fw-semibold">Internal error</span>';
        });
}

/*******************************
 * Other
 *******************************/
async function getPopup(id, context, target, admin, popupType) {
    const grayOut = document.querySelector("#gray_out");
    const loadingIcons = document.querySelectorAll(".loading");
    if (!popupType) popupType = '#popover_form';
    const popupElement = document.querySelector(popupType);

    if (grayOut) {
        grayOut.style.display = "block";
        grayOut.style.opacity = "1";
    }

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
            openPopup(popupType, false);
        }
    } catch (error) {
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

function toggleSecret(fieldId, btn) {
    const input = document.getElementById(fieldId);
    const icon = btn.querySelector('i');

    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.replace('fa-eye', 'fa-eye-slash');
        btn.classList.add('text-primary');
    } else {
        input.type = 'password';
        icon.classList.replace('fa-eye-slash', 'fa-eye');
        btn.classList.remove('text-primary');
    }
}


/*******************************
 * Template Element Add
 *******************************/
function initTemplateElementForm(container) {
    const form = container.querySelector('#templateElementAddForm');
    if (!form) return;

    const configDataNode = container.querySelector('#templateElementFormConfig');
    if (!configDataNode) return;

    let configData = {};
    try {
        configData = JSON.parse(configDataNode.textContent);
    } catch (e) {
        console.error("Erreur de parsing JSON pour le template element form", e);
        return;
    }

    const typeSelectorEl = container.querySelector('#ElementTypeSelector');
    const categoryEl = container.querySelector('#DynamicCategory');
    const typeEl = container.querySelector('#DynamicType');

    const typeSelectorTs = typeSelectorEl ? typeSelectorEl.tomselect : null;
    const categoryTs = categoryEl ? categoryEl.tomselect : null;
    const typeTs = typeEl ? typeEl.tomselect : null;

    const dynamicFormFields = container.querySelector('#dynamicFormFields');
    const checkComplex = container.querySelector('#checkComplex');

    function toggleGroups(selectedType) {
        if (!selectedType) {
            dynamicFormFields.classList.add('d-none');
            return;
        }

        dynamicFormFields.classList.remove('d-none');
        container.querySelectorAll('.element-group-attr, .element-group-file').forEach(el => el.classList.add('d-none'));

        if (selectedType === 'attribute') {
            container.querySelectorAll('.element-group-attr').forEach(el => el.classList.remove('d-none'));
            populateCategoryDropdown('attribute');
        } else if (selectedType === 'file') {
            container.querySelectorAll('.element-group-file').forEach(el => el.classList.remove('d-none'));
            populateCategoryDropdown('file');
        }
    }

    function populateCategoryDropdown(mode) {
        if (!categoryTs) return;

        categoryTs.clear(true);
        categoryTs.clearOptions();
        categoryTs.addOption({value: '', text: 'Select Category...'});

        const options = (mode === 'attribute') ? configData.categoriesAttr : configData.categoriesFile;

        Object.keys(options).forEach(key => {
            categoryTs.addOption({value: key, text: options[key]});
        });
        categoryTs.refreshOptions(false);

        if (configData.preSelectedCategory) {
            categoryTs.setValue(configData.preSelectedCategory, true);
            if (mode === 'attribute') populateTypeDropdown();
        }
    }

    function populateTypeDropdown() {
        if (!typeTs || !categoryTs) return;

        const category = categoryTs.getValue();
        typeTs.clear(true);
        typeTs.clearOptions();
        typeTs.addOption({value: '', text: 'Select Type...'});

        if (!category) return;

        const isComplex = checkComplex && checkComplex.checked;
        let typesList = [];

        if (isComplex && configData.typeGroupCategoryMapping[category]) {
            typesList = configData.typeGroupCategoryMapping[category];
        } else if (!isComplex && configData.categoryTypesAttr[category]) {
            typesList = configData.categoryTypesAttr[category];
        }

        typesList.forEach(val => {
            typeTs.addOption({value: val, text: val});
        });

        typeTs.refreshOptions(false);

        if (configData.preSelectedType) {
            typeTs.setValue(configData.preSelectedType, true);
        }
    }

    if (typeSelectorTs) {
        typeSelectorTs.on('change', toggleGroups);
    }

    if (categoryTs) {
        categoryTs.on('change', () => {
            const elType = typeSelectorTs ? typeSelectorTs.getValue() : null;
            if (elType === 'attribute') {
                populateTypeDropdown();
            }
        });
    }

    if (checkComplex) {
        checkComplex.addEventListener('change', populateTypeDropdown);
    }

    if (typeSelectorTs) {
        const initialType = typeSelectorTs.getValue();
        if (initialType) toggleGroups(initialType);
    }
}


/**
 * Displays a success or error message
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

function copyToClipboard(btn, text) {
    const originalHtml = btn.innerHTML;

    const proceedCopy = () => {
        btn.innerHTML = '<i class="fas fa-check text-primary"></i>';

        const tooltip = bootstrap.Tooltip.getInstance(btn);
        if (tooltip) {
            btn.setAttribute('data-bs-original-title', 'Copied!');
            tooltip.show();
        }

        setTimeout(() => {
            btn.innerHTML = originalHtml;
            if (tooltip) {
                btn.setAttribute('data-bs-original-title', 'Copy to clipboard');
                tooltip.hide();
            }
        }, 2000);
    };

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(proceedCopy);
    } else {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        try {
            document.execCommand("copy");
            proceedCopy();
        } catch (err) {
            console.error('Fallback copy failed', err);
        }
        document.body.removeChild(textarea);
    }
}

function toggleFormats(button, containerId) {
    const container = document.getElementById(containerId);
    const extraFormats = container.querySelectorAll('.extra-format');
    const isExpanding = extraFormats[0].classList.contains('d-none');

    extraFormats.forEach(el => {
        if (isExpanding) {
            el.classList.remove('d-none');
            el.classList.add('animate__animated', 'animate__fadeIn');
        } else {
            el.classList.add('d-none');
        }
    });

    if (isExpanding) {
        button.innerHTML = '<i class="fas fa-minus small me-1"></i>';
        button.classList.replace('bg-dark', 'bg-primary');
        button.classList.replace('text-primary', 'text-dark');
    } else {
        button.innerHTML = '<i class="fas fa-plus small me-1"></i>' + extraFormats.length;
        button.classList.replace('bg-primary', 'bg-dark');
        button.classList.replace('text-dark', 'text-primary');
    }
}


/*******************************
 * Server Add/Edit
 *******************************/

function initServerForm(container) {
    const form = container.querySelector('#ServerEditForm') || container.querySelector('#ServerAddForm');
    if (!form) return;

    /**********************************
     * Organisation type logic
     **********************************/
    const orgType = container.querySelector('[name="data[Server][organisation_type]"], #ServerOrganisationType');

    const externalContainer = container.querySelector('#ServerExternalContainer');
    const localContainer    = container.querySelector('#ServerLocalContainer');
    const nameContainer     = container.querySelector('#ServerExternalNameContainer');
    const uuidContainer     = container.querySelector('#ServerExternalUuidContainer');

    function hideAllOrgFields() {
        if (externalContainer) externalContainer.style.display = 'none';
        if (localContainer)    localContainer.style.display = 'none';
        if (nameContainer)     nameContainer.style.display = 'none';
        if (uuidContainer)     uuidContainer.style.display = 'none';
    }

    function updateOrganisationFields() {
        if (!orgType) return;

        const value = orgType.value;

        hideAllOrgFields();
        switch (value) {
            case 'local':
            case '0':
                if (localContainer) localContainer.style.display = 'block';
                break;

            case 'external':
            case '1':
                if (externalContainer) externalContainer.style.display = 'block';
                break;


            case 'new':
            case '2':
                if (nameContainer) nameContainer.style.display = 'block';
                if (uuidContainer) uuidContainer.style.display = 'block';
                break;
        }
    }

    if (orgType) {
        orgType.addEventListener('change', updateOrganisationFields);
        updateOrganisationFields();
    }

    /**********************************
     * PEM certificate dropzones
     **********************************/
    container.querySelectorAll('.pem-dropzone').forEach(zone => {
        const inputId = zone.dataset.target;
        const input   = inputId ? container.querySelector('#' + inputId) : null;
        if (!input) return;

        zone.addEventListener('click', () => input.click());

        zone.addEventListener('keydown', e => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
        });

        zone.addEventListener('dragover', e => {
            e.preventDefault();
            zone.classList.add('pem-drag-over');
        });

        zone.addEventListener('dragleave', () => zone.classList.remove('pem-drag-over'));

        zone.addEventListener('drop', e => {
            e.preventDefault();
            zone.classList.remove('pem-drag-over');
            const file = e.dataTransfer.files[0];
            if (file) _setPemFile(zone, input, file);
        });

        input.addEventListener('change', () => {
            if (input.files[0]) _setPemFile(zone, input, input.files[0]);
        });
    });

    container.querySelectorAll('.pem-existing').forEach(marker => {
        const zone        = container.querySelector('#' + marker.dataset.zone);
        const input       = container.querySelector('#' + marker.dataset.input);
        const deleteField = container.querySelector('#' + marker.dataset.deleteField);
        const filename    = marker.dataset.filename;

        if (!zone || !input) return;

        // Displays the area as if a file were already loaded
        _setPemExisting(zone, input, deleteField, filename);

        marker.remove();
    });

    /**********************************
     * Sync Rules
     **********************************/

    const syncRuleStates = {}; // Map<string, string>  (value -> label)
    const typeFilterStates = {}; // direction -> { attributes: Map, objects: Map }

    function _renderPills(pillsEl, jsonInputEl, items, badgeClass, onUpdate) {
        pillsEl.innerHTML = '';
        items.forEach((label, value) => {
            const pill = document.createElement('span');
            pill.className = `badge d-inline-flex align-items-center gap-1 ${badgeClass}`;
            pill.style.cssText = 'font-size:.75rem;font-weight:500;padding:4px 8px;';
            pill.innerHTML =
                escapeHtml(label) +
                '<button type="button" class="btn-close btn-close-white ms-1" ' +
                'style="font-size:.55rem;" aria-label="Remove"></button>';
            pill.querySelector('.btn-close').addEventListener('click', () => {
                items.delete(value);
                _renderPills(pillsEl, jsonInputEl, items, badgeClass, onUpdate);
                if (typeof onUpdate === 'function') {
                    onUpdate();
                }
            });
            pillsEl.appendChild(pill);
        });
        jsonInputEl.value = JSON.stringify([...items.keys()]);
    }

    function _syncRuleRender(fieldKey) {
        const pillsEl  = container.querySelector('#SyncRulePills_' + fieldKey);
        const jsonEl   = container.querySelector('#SyncRuleJson_' + fieldKey);
        if (!pillsEl || !jsonEl) return;
        const items      = syncRuleStates[fieldKey] || new Map();
        const badgeClass = fieldKey.includes('blockedlist') ? 'text-bg-danger' : 'text-bg-success';
        const updateLabel = () => {
            const contextLabel = pillsEl.closest('.sync-rule-box')?.querySelector('.sync-rule-label');
            if (contextLabel) contextLabel.classList.toggle('d-none', items.size === 0);
        };
        _renderPills(pillsEl, jsonEl, items, badgeClass, updateLabel);
        updateLabel();
    }


    function _syncRuleAdd(fieldKey, value, label) {
        const trimmed = value.trim();
        if (!trimmed) return;
        if (!syncRuleStates[fieldKey]) syncRuleStates[fieldKey] = new Map();
        syncRuleStates[fieldKey].set(trimmed, (label || trimmed).trim());
        _syncRuleRender(fieldKey);
    }


    // Initializes the states using the existing JSON values (edit mode)
    container.querySelectorAll('.sync-rule-box').forEach(box => {
        const fieldKey = `${box.dataset.direction}_${box.dataset.type}_${box.dataset.list}`;
        const jsonInput = container.querySelector('#SyncRuleJson_' + fieldKey);
        syncRuleStates[fieldKey] = new Map();

        if (jsonInput && jsonInput.value && jsonInput.value !== '[]') {
            try {
                // In edit mode, we only have the IDs, we display the ID while waiting for TomSelect to be ready to resolve the labels
                const existing = JSON.parse(jsonInput.value);
                existing.forEach(v => syncRuleStates[fieldKey].set(String(v), String(v)));
                _syncRuleRender(fieldKey);
            } catch(e) {}
        }

        // "+" button and free text
        const addBtn   = box.querySelector('.sync-rule-add-btn');
        const freetext = box.querySelector('.sync-rule-freetext');

        if (addBtn && freetext) {
            addBtn.addEventListener('click', () => {
                _syncRuleAdd(fieldKey, freetext.value, freetext.value);
                freetext.value = '';
            });
            freetext.addEventListener('keydown', e => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    _syncRuleAdd(fieldKey, freetext.value, freetext.value);
                    freetext.value = '';
                }
            });
        }

        // TomSelect — retrieves the label from the selected option
        const selectEl = container.querySelector('#SyncRule_' + fieldKey + '_select');
        if (selectEl) {
            const waitForTs = setInterval(() => {
                if (!selectEl.tomselect) return;
                clearInterval(waitForTs);

                // Label resolution for preloaded values (edit mode)
                syncRuleStates[fieldKey].forEach((lbl, val) => {
                    const opt = selectEl.tomselect.options[val];
                    if (opt) syncRuleStates[fieldKey].set(val, opt.text);
                });
                _syncRuleRender(fieldKey);

                selectEl.tomselect.on('item_add', value => {
                    const opt   = selectEl.tomselect.options[value];
                    const label = opt ? opt.text : value;
                    _syncRuleAdd(fieldKey, value, label);
                    selectEl.tomselect.removeItem(value, true);
                });
            }, 50);
        }
    });

    /**********************************
     * Pull rules — fetch remote tags & orgs
     **********************************/
    const serverId = form.dataset.serverId || '';

    if (serverId) {
        fetch(baseurl + '/servers/queryAvailableSyncFilteringRules/' + serverId, {
            method: 'POST',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-CSRF-Token': getCsrfToken(),
            },
        })
            .then(r => r.json())
            .then(response => {
                const alertFetching = container.querySelector('.sync-pull-fetching');
                const alertSuccess  = container.querySelector('.sync-pull-success');
                const alertError    = container.querySelector('.sync-pull-error');

                if (response.error && response.error.length > 0) {
                    // We display the error and enable freetext only
                    if (alertFetching) alertFetching.classList.add('d-none');
                    if (alertError) {
                        alertError.classList.remove('d-none');
                        alertError.querySelector('.sync-pull-error-msg').textContent = response.error;
                    }

                    container.querySelectorAll('[data-remote="true"]').forEach(sel => {
                        sel.closest('div.mb-2')?.remove();
                    });
                    return;
                }

                const remoteTags  = response.data.tags          || [];
                const remoteOrgs  = response.data.organisations || [];

                container.querySelectorAll('[data-remote="true"]').forEach(selectEl => {
                    const fieldKey  = selectEl.dataset.fieldKey;
                    const isOrgSel  = fieldKey.includes('_orgs_');
                    const dataset   = isOrgSel ? remoteOrgs : remoteTags;

                    //  Wait until TomSelect is ready
                    const waitTs = setInterval(() => {
                        if (!selectEl.tomselect) return;
                        clearInterval(waitTs);

                        const ts = selectEl.tomselect;
                        ts.enable();
                        ts.clearOptions();

                        dataset.forEach(entry => {
                            if (entry.uuid !== undefined && entry.name !== undefined) {
                                ts.addOption({ value: entry.uuid, text: entry.name });
                            } else {
                                ts.addOption({ value: entry, text: entry });
                            }
                        });
                        ts.refreshOptions(false);

                        ts.on('item_add', value => {
                            const opt   = ts.options[value];
                            const label = opt ? opt.text : value;
                            _syncRuleAdd(fieldKey, value, label);
                            ts.removeItem(value, true);
                        });
                    }, 50);
                });

                if (alertFetching) alertFetching.classList.add('d-none');
                if (alertSuccess)  alertSuccess.classList.remove('d-none');
            })
            .catch(err => {
                const alertFetching = container.querySelector('.sync-pull-fetching');
                const alertError    = container.querySelector('.sync-pull-error');
                if (alertFetching) alertFetching.classList.add('d-none');
                if (alertError) {
                    alertError.classList.remove('d-none');
                    alertError.querySelector('.sync-pull-error-msg').textContent =
                        'Connection error — ' + err.message;
                }
            });
    }

    /**********************************
     * Type Filtering Rules
     **********************************/

    function _typeFilterRender(direction, scope) {
        const pillsEl = container.querySelector(`#TypeFilterPills_${direction}_${scope}`);
        const jsonEl  = container.querySelector(`#TypeFilterJson_${direction}_${scope}`);
        if (!pillsEl || !jsonEl) return;
        const items = typeFilterStates[direction]?.[scope] || new Map();
        _renderPills(pillsEl, jsonEl, items, 'text-bg-danger');
    }

    ['push', 'pull'].forEach(direction => {
        typeFilterStates[direction] = { attributes: new Map(), objects: new Map() };

        ['attributes', 'objects'].forEach(scope => {
            const jsonInput = container.querySelector(`#TypeFilterJson_${direction}_${scope}`);
            if (!jsonInput || !jsonInput.value || jsonInput.value === '[]') return;
            try {
                const existing = JSON.parse(jsonInput.value);
                existing.forEach(v => typeFilterStates[direction][scope].set(String(v), String(v)));
                _typeFilterRender(direction, scope);
            } catch(e) {}

            const selectEl = container.querySelector(`#TypeFilterSelect_${direction}_${scope}`);
            if (!selectEl) return;
            const waitForTs = setInterval(() => {
                if (!selectEl.tomselect) return;
                clearInterval(waitForTs);
                typeFilterStates[direction][scope].forEach((lbl, val) => {
                    const opt = selectEl.tomselect.options[val];
                    if (opt) typeFilterStates[direction][scope].set(val, opt.text);
                });
                _typeFilterRender(direction, scope);
            }, 50);
        });

        // Main toggle — shows/hides the warning block
        const toggleCb  = container.querySelector('#typeFilteringEnable_' + direction);
        const warningEl = container.querySelector('#typeFilteringWarning_' + direction);
        if (toggleCb && warningEl) {
            toggleCb.addEventListener('change', () => {
                warningEl.classList.toggle('d-none', !toggleCb.checked);
                // If we uncheck the checkbox, we also uncheck the selected items and clear the confirmations
                if (!toggleCb.checked) {
                    const confirmCb  = container.querySelector('#typeFilteringConfirm_' + direction);
                    const selectsEl  = container.querySelector('#typeFilteringSelects_' + direction);
                    if (confirmCb)  confirmCb.checked = false;
                    if (selectsEl)  selectsEl.classList.add('d-none');
                    // Vider les states
                    typeFilterStates[direction].attributes.clear();
                    typeFilterStates[direction].objects.clear();
                    _typeFilterRender(direction, 'attributes');
                    _typeFilterRender(direction, 'objects');
                }
            });
        }

        // Confirmation checkbox — shows/hides the dropdown menus
        const confirmCb = container.querySelector('#typeFilteringConfirm_' + direction);
        const selectsEl = container.querySelector('#typeFilteringSelects_' + direction);
        if (confirmCb && selectsEl) {
            confirmCb.addEventListener('change', () => {
                selectsEl.classList.toggle('d-none', !confirmCb.checked);
            });
        }

        // TomSelect — listens for item_add on both select elements
        ['attributes', 'objects'].forEach(scope => {
            const scopeKey = scope === 'attributes' ? 'attributes' : 'objects';
            const selectEl = container.querySelector(
                '#TypeFilterSelect_' + direction + '_' + scope
            );
            if (!selectEl) return;

            const waitTs = setInterval(() => {
                if (!selectEl.tomselect) return;
                clearInterval(waitTs);

                selectEl.tomselect.on('item_add', value => {
                    const opt   = selectEl.tomselect.options[value];
                    const label = opt ? opt.text : value;
                    typeFilterStates[direction][scopeKey].set(value, label);
                    _typeFilterRender(direction, scope);
                    selectEl.tomselect.removeItem(value, true);
                });
            }, 50);
        });
    });


    /**********************************
     * url_params — JSON validation
     **********************************/
    const urlParamsEl  = container.querySelector('#SyncRulePullUrlParams');
    const urlParamsErr = container.querySelector('#SyncRulePullUrlParamsError');

    if (urlParamsEl) {
        urlParamsEl.addEventListener('blur', function () {
            const val = urlParamsEl.value.trim();
            if (!val) {
                urlParamsEl.classList.remove('is-invalid', 'is-valid');
                return;
            }
            try {
                JSON.parse(val);
                urlParamsEl.classList.remove('is-invalid');
                urlParamsEl.classList.add('is-valid');
                if (urlParamsErr) urlParamsErr.textContent = '';
            } catch (e) {
                urlParamsEl.classList.remove('is-valid');
                urlParamsEl.classList.add('is-invalid');
                if (urlParamsErr) urlParamsErr.textContent = e.message;
            }
        });
    }



    /**********************************
     * Debug helper
     **********************************/
    //console.log('[initServerForm] initialized');
}

function serverSubmitForm(action) {
    const form = document.getElementById('Server' + action + 'Form');
    if (!form) return;

    // ── 1. JSON Setup ──────────────────────────────────────────────────
    let ajax = {};
    const orgType = document.getElementById('ServerOrganisationType').value;
    switch (orgType) {
        case '0': ajax = { id: document.getElementById('ServerLocal').value };    break;
        case '1': ajax = { id: document.getElementById('ServerExternal').value }; break;
        case '2':
            ajax = {
                name: document.getElementById('ServerExternalName').value,
                uuid: document.getElementById('ServerExternalUuid').value
            };
            break;
    }
    document.getElementById('ServerJson').value = JSON.stringify(ajax);

    // ── 2. Read a SyncRuleJson field (returns [] if missing or invalid) ────────
    function readJsonField(id) {
        const el = form.querySelector('#' + id);
        if (!el) return [];
        try { return JSON.parse(el.value) || []; } catch { return []; }
    }

    // ── 3. Build push_rules ──────────────────────────────────────────────
    const pushRules = {
        tags: {
            OR:  readJsonField('SyncRuleJson_push_tags_allowedlist'),
            NOT: readJsonField('SyncRuleJson_push_tags_blockedlist'),
        },
        orgs: {
            OR:  readJsonField('SyncRuleJson_push_orgs_allowedlist'),
            NOT: readJsonField('SyncRuleJson_push_orgs_blockedlist'),
        },
        type_attributes: {
            NOT: readJsonField('TypeFilterJson_push_attributes'),
        },
        type_objects: {
            NOT: readJsonField('TypeFilterJson_push_objects'),
        },
    };

    const pushRulesField = form.querySelector('[name="data[Server][push_rules]"]');
    if (pushRulesField) pushRulesField.value = JSON.stringify(pushRules);

    // ── 4. Build pull_rules ──────────────────────────────────────────────
    const pullRules = {
        tags: {
            OR:  readJsonField('SyncRuleJson_pull_tags_allowedlist'),
            NOT: readJsonField('SyncRuleJson_pull_tags_blockedlist'),
        },
        orgs: {
            OR:  readJsonField('SyncRuleJson_pull_orgs_allowedlist'),
            NOT: readJsonField('SyncRuleJson_pull_orgs_blockedlist'),
        },
        type_attributes: {
            NOT: readJsonField('TypeFilterJson_pull_attributes'),
        },
        type_objects: {
            NOT: readJsonField('TypeFilterJson_pull_objects'),
        },
        url_params: '',
    };

    // Inject url_params from the textarea (without submitting it directly)
    const urlParamsEl = form.querySelector('#SyncRulePullUrlParams');
    if (urlParamsEl) {
        const raw = urlParamsEl.value.trim();
        if (raw) {
            // Validate that it is valid JSON, but store the raw string
            try {
                JSON.parse(raw);
                pullRules.url_params = raw;
            } catch {
                pullRules.url_params = raw;
            }
        } else {
            pullRules.url_params = '';
        }
    }

    const pullRulesField = form.querySelector('[name="data[Server][pull_rules]"]');
    if (pullRulesField) pullRulesField.value = JSON.stringify(pullRules);

    form.submit();
}


function _setPemFile(zone, input, file) {
    _renderPemZone(zone, input, file.name, null, null);
}

function _setPemExisting(zone, input, deleteField, filename) {
    _renderPemZone(zone, input, filename, deleteField, () => {
        if (deleteField) deleteField.checked = true;
    });
}

function _renderPemZone(zone, input, filename, deleteField, onRemoveExtra) {
    zone.classList.add('pem-has-file');
    const hint = zone.querySelector('.pem-hint');
    const icon = zone.querySelector('.pem-icon');
    const name = zone.querySelector('.pem-filename');
    if (!name) return;

    if (hint) hint.classList.add('d-none');
    if (icon) icon.classList.add('d-none');

    name.classList.remove('d-none');
    name.innerHTML =
        '<i class="fas fa-file-certificate me-1"></i>' + escapeHtml(filename) +
        ' <button type="button" class="pem-remove-btn" aria-label="Remove file">' +
        '<i class="fas fa-trash-alt"></i></button>';

    name.querySelector('.pem-remove-btn').addEventListener('click', e => {
        e.stopPropagation();
        input.value = '';
        zone.classList.remove('pem-has-file');
        name.classList.add('d-none');
        name.innerHTML = '';
        if (hint) hint.classList.remove('d-none');
        if (icon) icon.classList.remove('d-none');
        if (onRemoveExtra) onRemoveExtra();
    });
}



function _onTomSelectReady(el, callback) {
    if (!el) return;
    const interval = setInterval(() => {
        if (!el.tomselect) return;
        clearInterval(interval);
        callback(el.tomselect);
    }, 50);
}




/*******************************
 * Sharing Group Add/Edit
 *******************************/

function initSharingGroupForm(container) {
    const form = container.querySelector('#sharingGroupForm');
    if (!form) return;

    const orgState    = new Map();  // organisations : Map<id|uuid, { id, name, type, uuid, extend, removable }>
    const serverState = new Map();  // servers       : Map<id,      { id, name, url,  all_orgs, removable }>

    // ── Helpers DOM ───────────────────────────────────────────────────────────
    const orgsBody    = container.querySelector('#organisations_table_body');
    const serversBody = container.querySelector('#servers_table_body');
    const jsonInput   = container.querySelector('#SharingGroupJson');
    const roamingCb   = container.querySelector('#SharingGroupRoaming');
    const serverList  = container.querySelector('#serverList');

    // ── Organisations table display ────────────────────────────────────────
    function renderOrgs() {
        if (!orgsBody) return;
        orgsBody.innerHTML = '';

        orgState.forEach((org, key) => {
            const tr = document.createElement('tr');
            // Badge type
            const typeBadge = org.type === 'local'
                ? '<span class="badge text-bg-success">Local</span>'
                : '<span class="badge text-bg-secondary">External</span>';

            // Toggle extend
            const extendChecked = org.extend ? 'checked' : '';
            const removableAttr = org.removable === false ? 'disabled' : '';

            tr.innerHTML = `
                <td>${typeBadge}</td>
                <td>${escapeHtml(org.name)}</td>
                <td><small class="text-muted">${escapeHtml(org.uuid || '—')}</small></td>
                <td>
                    <div class="form-check form-switch mb-0">
                        <input class="form-check-input sg-org-extend"
                               type="checkbox"
                               data-key="${escapeHtml(key)}"
                               ${extendChecked}
                               ${removableAttr}
                               title="${escapeHtml('Allow this organisation to extend the sharing group')}">
                    </div>
                </td>
                <td>
                    ${org.removable !== false
                        ? `<button type="button" class="btn btn-sm btn-outline-danger sg-org-remove" data-key="${escapeHtml(key)}">
                               <i class="fas fa-trash-alt"></i>
                           </button>`
                        : '<span class="text-muted small">—</span>'
                    }
                </td>`;

            // Extend toggle
            tr.querySelector('.sg-org-extend')?.addEventListener('change', e => {
                orgState.get(key).extend = e.target.checked;
                _updateSummary();
            });

            // Remove
            tr.querySelector('.sg-org-remove')?.addEventListener('click', () => {
                orgState.delete(key);
                renderOrgs();
                _updateSummary();
            });

            orgsBody.appendChild(tr);
        });

        _updateSummary();
    }

    // ── Servers table display ──────────────────────────────────────────────
    function renderServers() {
        if (!serversBody) return;
        serversBody.innerHTML = '';

        serverState.forEach((srv, key) => {
            const tr = document.createElement('tr');
            const allOrgsChecked = srv.all_orgs ? 'checked' : '';
            const removableAttr  = srv.removable === false ? 'disabled' : '';

            tr.innerHTML = `
                <td>${escapeHtml(srv.name)}</td>
                <td><small class="text-muted">${escapeHtml(srv.url || '—')}</small></td>
                <td>
                    <div class="form-check form-switch mb-0">
                        <input class="form-check-input sg-srv-allorgs"
                               type="checkbox"
                               data-key="${escapeHtml(key)}"
                               ${allOrgsChecked}
                               ${removableAttr}
                               title="${escapeHtml('Sync with all organisations on this instance')}">
                    </div>
                </td>
                <td>
                    ${srv.removable !== false
                        ? `<button type="button" class="btn btn-sm btn-outline-danger sg-srv-remove" data-key="${escapeHtml(key)}">
                               <i class="fas fa-trash-alt"></i>
                           </button>`
                        : '<span class="text-muted small">—</span>'
                    }
                </td>`;

            tr.querySelector('.sg-srv-allorgs')?.addEventListener('change', e => {
                serverState.get(key).all_orgs = e.target.checked;
                _updateSummary();
            });

            tr.querySelector('.sg-srv-remove')?.addEventListener('click', () => {
                serverState.delete(key);
                renderServers();
                _updateSummary();
            });

            serversBody.appendChild(tr);
        });

        _updateSummary();
    }

    // ── Local orgs ────────────────────────────────────────────────────────────────
    _onTomSelectReady(container.querySelector('#sg-local-org-select'), ts => {
        ts.on('item_add', value => {
            ts.removeItem(value, true);
            if (orgState.has(value)) return;
            const opt  = ts.options[value];
            const meta = (typeof sgOrgMeta !== 'undefined') ? (sgOrgMeta[value] || {}) : {};
            orgState.set(value, {
                id:        value,
                name:      opt?.text || value,
                type:      'local',
                uuid:      meta.uuid || '',
                extend:    false,
                removable: true,
            });
            renderOrgs();
        });
    });

    // ── External orgs ─────────────────────────────────────────────────────────────
    _onTomSelectReady(container.querySelector('#sg-ext-org-select'), ts => {
        ts.on('item_add', value => {
            ts.removeItem(value, true);
            if (orgState.has(value)) return;
            const opt  = ts.options[value];
            const meta = (typeof sgOrgMeta !== 'undefined') ? (sgOrgMeta[value] || {}) : {};
            orgState.set(value, {
                id:        value,
                name:      opt?.text || value,
                type:      'external',
                uuid:      meta.uuid || '',
                extend:    false,
                removable: true,
            });
            renderOrgs();
        });
    });

    // ── Servers ───────────────────────────────────────────────────────────────────
    _onTomSelectReady(container.querySelector('#sg-server-select'), ts => {
        ts.on('item_add', value => {
            ts.removeItem(value, true);
            if (serverState.has(value)) return;
            const opt  = ts.options[value];
            const meta = (typeof sgServerMeta !== 'undefined') ? (sgServerMeta[value] || {}) : {};
            serverState.set(value, {
                id:        value,
                name:      opt?.text || value,
                url:       meta.url  || '',
                all_orgs:  false,
                removable: true,
            });
            renderServers();
        });
    });



    // ── Roaming toggle ────────────────────────────────────────────────────────
    roamingCb?.addEventListener('change', () => {
        if (serverList) serverList.style.display = roamingCb.checked ? 'none' : 'block';
        _updateSummary();
    });

    // ── Navigation accordion (Next / Prev) ────────────────────────────────────
    container.querySelectorAll('.sg-next').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.next;
            const target   = container.querySelector('#' + targetId);
            if (target) new bootstrap.Collapse(target, { toggle: false }).show();
        });
    });

    container.querySelectorAll('.sg-prev').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.dataset.prev;
            const target   = container.querySelector('#' + targetId);
            if (target) new bootstrap.Collapse(target, { toggle: false }).show();
        });
    });

    // ── Résumé (Step 4) ───────────────────────────────────────────────────────
    function _updateSummary() {
        const name         = container.querySelector('#SharingGroupName')?.value        || '—';
        const releasable   = container.querySelector('#SharingGroupReleasability')?.value || '—';

        _setText('summarytitle',      name);
        _setText('summaryreleasable', releasable);

        // Local orgs
        const localOrgs    = [...orgState.values()].filter(o => o.type === 'local');
        const localExtend  = localOrgs.filter(o => o.extend);
        _setText('summarylocal',       localOrgs.length   ? localOrgs.map(o => o.name).join(', ')   : '—');
        _setText('summarylocalextend', localExtend.length ? localExtend.map(o => o.name).join(', ') : ('none'));

        // External orgs
        const extOrgs      = [...orgState.values()].filter(o => o.type === 'external');
        const extExtend    = extOrgs.filter(o => o.extend);
        _setText('summaryexternal',       extOrgs.length   ? extOrgs.map(o => o.name).join(', ')   : '—');
        _setText('summaryexternalextend', extExtend.length ? extExtend.map(o => o.name).join(', ') : ('none'));

        // Servers
        const roaming = roamingCb?.checked;
        const srvText = roaming
            ? ('Roaming mode — any connected instance')
            : ([...serverState.values()].map(s => s.name).join(', ') || '—');
        _setText('summaryservers', srvText);
    }

    function _setText(id, text) {
        const el = container.querySelector('#' + id);
        if (el) el.textContent = text;
    }

    // Resume update from Step 1
    ['SharingGroupName', 'SharingGroupReleasability'].forEach(id => {
        container.querySelector('#' + id)?.addEventListener('input', _updateSummary);
    });

    // ── Submit ────────────────────────────────────────────────────────────────
    container.querySelector('#sg-submit-btn')?.addEventListener('click', () => {
        const name = container.querySelector('#SharingGroupName')?.value.trim();
        if (!name) {
            const step1 = container.querySelector('#sgCollapse1');
            if (step1) new bootstrap.Collapse(step1, { toggle: false }).show();
            form.classList.add('was-validated');
            return;
        }

        const payload = {
            sharingGroup: {
                name:          name,
                releasability: container.querySelector('#SharingGroupReleasability')?.value.trim() || '',
                description:   container.querySelector('#SharingGroupDescription')?.value.trim()   || '',
                active:        container.querySelector('#SharingGroupActive')?.checked  ? 1 : 0,
                roaming:       container.querySelector('#SharingGroupRoaming')?.checked ? 1 : 0,
                uuid:          container.querySelector('#SharingGroupUuid')?.value.trim() || undefined,
            },
            organisations: [...orgState.values()].map(o => ({
                id:     o.id,
                name:   o.name,
                type:   o.type,
                uuid:   o.uuid || '',
                extend: o.extend ? 1 : 0,
            })),
            servers: [...serverState.values()].map(s => ({
                id:       s.id,
                name:     s.name,
                url:      s.url,
                all_orgs: s.all_orgs ? 1 : 0,
            })),
        };

        if (jsonInput) jsonInput.value = JSON.stringify(payload);
        form.submit();
    });

    // ── Initialization in edit mode ───────────────────────────────────────────
    // The controller passes $sharingGroup along with SharingGroupOrg and SharingGroupServer
    // We initialize the two Maps using the inline PHP data
    if (typeof sgInitData !== 'undefined' && sgInitData) {
        (sgInitData.organisations || []).forEach(o => {
            const key = String(o.id);
            orgState.set(key, {
                id:        o.id,
                name:      o.name,
                type:      o.type,
                uuid:      o.uuid || '',
                extend:    !!o.extend,
                removable: o.removable !== false,
            });
        });
        (sgInitData.servers || []).forEach(s => {
            const key = String(s.id || s.Server?.id);
            serverState.set(key, {
                id:        s.Server?.id || s.id,
                name:      s.Server?.name || s.name || key,
                url:       s.Server?.url  || s.url  || '',
                all_orgs:  !!s.all_orgs,
                removable: s.removable !== false,
            });
        });
        renderOrgs();
        renderServers();

        // Step 1
        if (sgInitData.sharingGroup) {
            const sg = sgInitData.sharingGroup;
            ['Name', 'Releasability', 'Description'].forEach(f => {
                const el = container.querySelector('#SharingGroup' + f);
                if (el && sg[f.toLowerCase()] !== undefined) el.value = sg[f.toLowerCase()];
            });
            if (sg.active  !== undefined && container.querySelector('#SharingGroupActive'))
                container.querySelector('#SharingGroupActive').checked = !!sg.active;
            if (sg.roaming !== undefined && roamingCb)  {
                roamingCb.checked = !!sg.roaming;
                if (serverList) serverList.style.display = roamingCb.checked ? 'none' : 'block';
            }
        }
        _updateSummary();
    } else {
        if (typeof sgDefaultOrg !== 'undefined' && sgDefaultOrg) {
            const key = String(sgDefaultOrg.id);
            orgState.set(key, { ...sgDefaultOrg, removable: false });
        }
        if (typeof sgDefaultServer !== 'undefined' && sgDefaultServer) {
            const key = String(sgDefaultServer.id);
            serverState.set(key, { ...sgDefaultServer, removable: false });
        }
        renderOrgs();
        renderServers();
    }
}