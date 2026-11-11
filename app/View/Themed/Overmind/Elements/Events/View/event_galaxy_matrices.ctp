<?php
$eventId  = h($data['Event']['id'] ?? '');
$uid      = 'evt-matrices-' . $eventId;
$fetchUrl = $baseurl . '/events/viewEventGalaxyMatrices/' . $eventId
    . ($extensionSuffix ?? '');
?>

<div class="card shadow-sm mb-3 d-none" id="<?= $uid ?>">

    <div class="d-flex align-items-center gap-2 px-3 pt-3">
        <div class="rounded-2 d-flex align-items-center justify-content-center flex-shrink-0 bg-galaxy bg-opacity-10"
             style="width:36px;height:36px;">
            <i class="fas fa-map text-galaxy"></i>
        </div>
        <div class="me-auto text-truncate">
            <div class="fw-bold lh-1 text-truncate" id="<?= $uid ?>-title"><?= __('Matrix galaxies') ?></div>
            <div class="small text-muted mt-1 text-truncate" id="<?= $uid ?>-summary"></div>
        </div>
        <button type="button"
                class="btn btn-sm btn-outline-secondary flex-shrink-0"
                id="<?= $uid ?>-expand"
                title="<?= __('Show every tactic of the matrix') ?>">
            <i class="fas fa-expand"></i>
        </button>
    </div>

    <div id="<?= $uid ?>-body" data-collapse-tall="420"></div>

</div>

<script>
(function () {
    var uid      = <?= json_encode($uid) ?>;
    var fetchUrl = <?= json_encode($fetchUrl) ?>;
    var card     = document.getElementById(uid);
    var body     = document.getElementById(uid + '-body');
    var titleEl  = document.getElementById(uid + '-title');
    var summary  = document.getElementById(uid + '-summary');
    var selected = null;

    document.getElementById(uid + '-expand').addEventListener('click', function () {
        openModal(fetchUrl + '/full:1/galaxy:' + encodeURIComponent(selected || ''), 'fullscreen');
    });

    body.addEventListener('click', function (event) {
        var button = event.target.closest('[data-matrix-switch]');
        if (button) { select(button.getAttribute('data-matrix-switch')); }
    });

    /* The galaxy card's edit and relationship modals announce a save. */
    document.addEventListener('misp:event-galaxies-changed', load);
    load();

    function load() {
        fetch(fetchUrl, { credentials: 'same-origin' })
            .then(function (r) {
                if (!r.ok) { throw new Error(r.status); }
                return r.text();
            })
            .then(function (html) {
                body.innerHTML = html;
                var root  = body.querySelector('[data-matrix-count]');
                var count = root ? parseInt(root.getAttribute('data-matrix-count'), 10) : 0;
                card.classList.toggle('d-none', !count);
                if (!count) { selected = null; return; }

                titleEl.textContent = root.getAttribute('data-matrix-title');
                var keep = selected
                    && body.querySelector('[data-matrix-switch="' + selected + '"]');
                select(keep
                    ? selected
                    : body.querySelector('[data-matrix-switch]').getAttribute('data-matrix-switch'));
            })
            .catch(function () {
                card.classList.add('d-none');
            });
    }

    function select(id) {
        selected = id;
        body.querySelectorAll('[data-matrix-switch]').forEach(function (button) {
            var on = button.getAttribute('data-matrix-switch') === id;
            button.setAttribute('aria-pressed', on ? 'true' : 'false');
            button.classList.toggle('bg-body', on);
            button.classList.toggle('shadow-sm', on);
            button.classList.toggle('fw-semibold', on);
            button.classList.toggle('text-body-secondary', !on);
        });
        body.querySelectorAll('[data-matrix-panel]').forEach(function (panel) {
            var on = panel.getAttribute('data-matrix-panel') === id;
            panel.classList.toggle('d-none', !on);
            if (on) { summary.textContent = panel.getAttribute('data-matrix-summary'); }
        });
    }
}());
</script>
