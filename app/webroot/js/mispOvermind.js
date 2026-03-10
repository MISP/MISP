 function openModal(url) {
    fetch(url)
        .then(response => response.text())
        .then(html => {
            document.getElementById('mainModalBody').innerHTML = html;
            let modal = new bootstrap.Modal(document.getElementById('mainModal'));
            modal.show();
        });
}

function multiSelectEvents(url) {
    if (selectedEvents.size === 0) {
        return;
    }
    const ids = Array.from(selectedEvents.keys());
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