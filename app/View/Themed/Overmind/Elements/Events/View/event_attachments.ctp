<?php
$eventId   = h($data['Event']['id'] ?? '');
$uid       = 'ea-' . $eventId;
$fetchUrl  = h($baseurl . '/events/viewAttachments/' . $eventId);
$uploadUrl = h($baseurl . '/attributes/add_attachment/' . $eventId);
$mayModify = $this->Acl->canModifyEvent($data);
?>

<div class="card shadow-sm eo-card eo-attachments" id="attachment-card">

    <div class="eo-card-head eo-attach-head">
        <div class="misp-icon-tile eo-tile" style="--tile:#F59E0B;--tile-bg:#fff3cd;">
            <i class="fas fa-paperclip"></i>
        </div>
        <div class="min-w-0 me-auto">
            <div class="eo-card-title"><?= __('Attachments') ?></div>
            <div class="eo-card-sub" id="<?= $uid ?>-count">…</div>
        </div>

        <div class="input-group input-group-sm eo-attach-search d-none" id="<?= $uid ?>-filter">
            <span class="input-group-text"><i class="fas fa-search"></i></span>
            <input type="search"
                   id="<?= $uid ?>-search"
                   class="form-control"
                   placeholder="<?= __('Filter files, hashes…') ?>"
                   autocomplete="off"
                   aria-label="<?= __('Filter attachments') ?>">
        </div>

        <span class="d-inline-flex gap-1 flex-shrink-0">
            <?php if ($mayModify || $isSiteAdmin): ?>
                <a href="<?= $uploadUrl ?>"
                   onclick="event.preventDefault(); openModal('<?= $uploadUrl ?>')"
                   class="btn btn-sm btn-outline-primary d-inline-flex align-items-center gap-1">
                    <i class="fas fa-upload"></i><?= __('Upload') ?>
                </a>
            <?php endif; ?>
            <button type="button"
                    id="<?= $uid ?>-dl-all"
                    class="btn btn-sm btn-primary d-inline-flex align-items-center gap-1 d-none"
                    onclick="eaDownloadAll('<?= $uid ?>')"
                    title="<?= __('Download every file shown') ?>">
                <i class="fas fa-download"></i><?= __('Download all') ?>
            </button>
        </span>
    </div>

    <div id="<?= $uid ?>-body" data-collapse-tall="300">
        <div class="text-center py-5 text-muted" id="<?= $uid ?>-spinner">
            <div class="misp-loader misp-loader-sm" role="status"></div>
        </div>
    </div>

</div>

<script>
(function () {
    var uid      = <?= json_encode($uid) ?>;
    var body     = document.getElementById(uid + '-body');
    var search   = document.getElementById(uid + '-search');
    var countEl  = document.getElementById(uid + '-count');
    var fetchUrl = <?= json_encode($fetchUrl) ?>;

    fetch(fetchUrl)
        .then(function (r) {
            if (!r.ok) { throw new Error(r.status); }
            return r.text();
        })
        .then(function (html) {
            body.innerHTML = html;
            var root  = body.querySelector('[data-attachment-count]');
            var total = root ? parseInt(root.getAttribute('data-attachment-count'), 10) : 0;
            setCount(total, total);
            bindSearch(total);
            var filter = document.getElementById(uid + '-filter');
            var dlBtn = document.getElementById(uid + '-dl-all');
            if (filter) { filter.classList.toggle('d-none', total <= 3); }
            if (dlBtn) { dlBtn.classList.toggle('d-none', total <= 1); }
        })
        .catch(function () {
            body.innerHTML =
                '<div class="text-center text-muted py-4 small">'
                + '<i class="fas fa-exclamation-triangle me-2"></i>'
                + <?= json_encode(__('Could not load attachments.')) ?>
                + '</div>';
            if (countEl) { countEl.textContent = ''; }
        });

    function setCount(total, visible) {
        if (!countEl) { return; }
        var files = total === 1
            ? <?= json_encode(__('1 file')) ?>
            : total + ' ' + <?= json_encode(__('files')) ?>;
        if (total === 0) {
            countEl.textContent = <?= json_encode(__('No files')) ?>;
        } else if (visible === total) {
            countEl.textContent = files;
        } else {
            countEl.textContent =
                files + ' · ' + visible + ' ' + <?= json_encode(__('visible')) ?>;
        }
    }

    function bindSearch(total) {
        if (!search) { return; }
        search.addEventListener('input', function () {
            applySearch(total);
        });
    }

    function applySearch(total) {
        var q        = search.value.toLowerCase().trim();
        var rows     = body.querySelectorAll('[data-attachment-row]');
        var noResult = body.querySelector('[data-attachment-noresult]');
        var visible  = 0;

        rows.forEach(function (row) {
            var text = row.getAttribute('data-search-text') || '';
            var show = (q === '' || text.includes(q));
            row.style.display = show ? '' : 'none';
            if (show) { visible++; }
        });

        if (noResult) {
            noResult.classList.toggle(
                'd-none', visible > 0 || rows.length === 0
            );
        }

        setCount(total, visible);
    }
}());

/* Download All — triggers sequential individual downloads for visible rows */
if (typeof eaDownloadAll === 'undefined') {
    window.eaDownloadAll = function (uid) {
        var body = document.getElementById(uid + '-body');
        if (!body) { return; }
        var rows = body.querySelectorAll('[data-attachment-row]');
        var delay = 0;
        rows.forEach(function (row) {
            if (row.style.display === 'none') { return; }
            var link = row.querySelector('a[href]');
            if (!link) { return; }
            var href = link.getAttribute('href');
            setTimeout(function () {
                var a = document.createElement('a');
                a.href = href;
                a.download = '';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
            }, delay);
            delay += 400;
        });
    };
}
</script>
