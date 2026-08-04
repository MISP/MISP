<?php
$eventId   = h($data['Event']['id'] ?? '');
$uid       = 'ea-' . $eventId;
$fetchUrl  = h($baseurl . '/events/viewAttachments/' . $eventId);
$uploadUrl = h($baseurl . '/attributes/add_attachment/' . $eventId);
$mayModify = $this->Acl->canModifyEvent($data);
?>

<div class="card shadow-sm mb-3" id="attachment-card">

    <!-- HEADER -->
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">

            <!-- Icon + title + count -->
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="rounded-2 d-flex align-items-center justify-content-center"
                     style="width:36px;height:36px;background:#fff3cd;">
                    <i class="fas fa-paperclip" style="color:#F59E0B; font-size:1rem;"></i>
                </div>
                <div>
                    <div class="fw-bold lh-1">
                        <?= __('Event Attachments') ?>
                    </div>
                    <div class="small text-muted mt-1" id="<?= $uid ?>-count">
                        …
                    </div>
                </div>
            </div>

            <!-- Search -->
            <div class="input-group input-group-sm" style="max-width:300px;">
                <span class="input-group-text border-end-0 bg-white">
                    <i class="fas fa-search text-muted small"></i>
                </span>
                <input type="search"
                       id="<?= $uid ?>-search"
                       class="form-control border-start-0 ps-0"
                       placeholder="<?= __('Filter files, hashes, MIME…') ?>"
                       autocomplete="off"
                       aria-label="<?= __('Filter attachments') ?>">
            </div>

            <!-- Upload -->
            <?php if ($mayModify || $isSiteAdmin): ?>
            <a href="<?= $uploadUrl ?>"
               onclick="event.preventDefault(); openModal('<?= $uploadUrl ?>')"
               class="btn btn-sm btn-outline-secondary d-flex align-items-center gap-1">
                <i class="fas fa-upload"></i>
                <?= __('Upload') ?>
            </a>
            <?php endif; ?>

            <!-- Download All -->
            <button type="button"
                    id="<?= $uid ?>-dl-all"
                    class="btn btn-sm btn-primary d-flex align-items-center gap-1"
                    onclick="eaDownloadAll('<?= $uid ?>')"
                    disabled>
                <i class="fas fa-download"></i>
                <?= __('Download All') ?>
            </button>

        </div>
    </div>

    <!-- BODY -->
    <div class="card-body p-0" id="<?= $uid ?>-body">
        <div class="text-center py-5 text-muted" id="<?= $uid ?>-spinner">
            <div class="spinner-border spinner-border-sm" role="status"></div>
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
            /* enable Download All only when there's something to download */
            var dlBtn = document.getElementById(uid + '-dl-all');
            if (dlBtn && total > 0) { dlBtn.disabled = false; }
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
        if (total === 0) {
            countEl.textContent = <?= json_encode(__('No files')) ?>;
        } else if (visible === total) {
            countEl.textContent = total + ' ' + <?= json_encode(__('files')) ?>;
        } else {
            countEl.textContent =
                total + ' ' + <?= json_encode(__('files')) ?>
                + ' · ' + visible + ' ' + <?= json_encode(__('visible')) ?>;
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
