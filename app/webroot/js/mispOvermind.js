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
