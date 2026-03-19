/*******************************
 * Index Filtering Bar
 *******************************/
 
 function openModal(url) {
    fetch(url)
        .then(response => response.text())
        .then(html => {
            document.getElementById('mainModalBody').innerHTML = html;
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
    console.log(view)
    if (view === 'card') {
        console.log('ed')
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
    const editButton   = document.getElementById('mass-edit-button');
    const count          = selectedItems.size;

    if (count === 0) {
        toolbar?.classList.add('d-none');
        return;
    }

    toolbar?.classList.remove('d-none');
    if (selectedCount) selectedCount.textContent = count;

    let canDeleteAll = true;
    selectedItems.forEach(item => {
        if (!item.canDelete) canDeleteAll = false;
    });

    const isHidden = !canDeleteAll;

    deleteButton?.classList.toggle('d-none', isHidden);
    editButton?.classList.toggle('d-none', isHidden);
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

    const quickField = document.getElementById('quickFilterField');
    const quickValue = quickField ? quickField.value.trim() : '';

    delete filters['eventinfo'];
    delete filters['eventid'];

    if (quickValue !== '') {
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        const numberRegex = /^[0-9]+$/;

        if (uuidRegex.test(quickValue) || numberRegex.test(quickValue)) {
            filters['eventid'] = encodeURIComponent(quickValue);
        } else {
            filters['eventinfo'] = encodeURIComponent(quickValue);
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
    Object.keys(filters).forEach(key => {
        newUrl += '/search' + key + ':' + filters[key];
    });

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

        if (checkbox.checked) {
            selectedItems.set(id, { id, canDelete });
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