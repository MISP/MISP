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