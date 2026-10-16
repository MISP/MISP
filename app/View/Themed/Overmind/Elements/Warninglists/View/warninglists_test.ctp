<?php
/**
 * Test a value against this warninglist alone, by its own matching rule.
 * Drawn as a rail card; the answer comes from warninglists/testValue.
 */
$warninglistId = (int)$data['Warninglist']['id'];
?>
<section class="card shadow-sm mb-3 rcard-card rcard-shape-status" aria-label="<?= __('Test a value') ?>"
    data-rail-card="warninglist-test">
    <div class="rcard-head p-3 border-bottom">
        <div class="rcard-tile rounded-2"><i class="fas fa-vial rcard-ico" aria-hidden="true"></i></div>
        <div class="rcard-title fw-bold lh-1"><?= __('Test a value') ?></div>
    </div>
    <div class="rcard-body p-3">
        <form class="input-group input-group-sm" data-wl-test="<?= h($baseurl . '/warninglists/testValue/' . $warninglistId) ?>">
            <input type="text" class="form-control" name="value" required
                placeholder="<?= __('e.g. 8.8.8.8 or google.com') ?>" aria-label="<?= __('Value to test') ?>">
            <button type="submit" class="btn btn-outline-secondary"><?= __('Test') ?></button>
        </form>
        <div class="wl-test-result mt-3" aria-live="polite" hidden></div>
    </div>
</section>
<script>
if (!window.mispWarninglistTest) {
    window.mispWarninglistTest = true;
    document.addEventListener('submit', function (event) {
        var form = event.target.closest('[data-wl-test]');
        if (!form) {
            return;
        }
        event.preventDefault();
        var out = form.parentNode.querySelector('.wl-test-result');
        var value = form.elements.value.value.trim();
        if (value === '') {
            return;
        }
        var esc = function (text) {
            var span = document.createElement('span');
            span.textContent = text;
            return span.innerHTML;
        };
        var state = function (tone, icon, text) {
            return '<div class="rcard-state rcard-t-' + tone + '">'
                + '<span class="rcard-state-dot rcard-fill-' + tone + '" aria-hidden="true"><i class="fas fa-' + icon + '"></i></span>'
                + '<p class="rcard-state-text">' + text + '</p></div>';
        };
        out.hidden = false;
        out.innerHTML = '<div class="misp-loader misp-loader-sm" role="status"></div>';
        fetch(form.dataset.wlTest + '?value=' + encodeURIComponent(value), {
            headers: {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
            credentials: 'same-origin'
        }).then(function (response) {
            if (!response.ok) {
                throw new Error(response.statusText);
            }
            return response.json();
        }).then(function (result) {
            if (!result.hit) {
                out.innerHTML = state('ok', 'check', <?= json_encode(h(__('No hit: this list does not match %s.'))) ?>.replace('%s', '<strong>' + esc(result.value) + '</strong>'));
                return;
            }
            var rows = '<div class="rcard-kv-row"><dt class="rcard-kv-label">' + <?= json_encode(h(__('Matched entry'))) ?> + '</dt>'
                + '<dd class="rcard-kv-value" title="' + esc(result.matched) + '">' + esc(result.matched) + '</dd></div>';
            if (result.comment) {
                rows += '<div class="rcard-kv-row"><dt class="rcard-kv-label">' + <?= json_encode(h(__('Comment'))) ?> + '</dt>'
                    + '<dd class="rcard-kv-value" title="' + esc(result.comment) + '">' + esc(result.comment) + '</dd></div>';
            }
            out.innerHTML = state('warn', 'exclamation', <?= json_encode(h(__('Hit: this list matches %s.'))) ?>.replace('%s', '<strong>' + esc(result.value) + '</strong>'))
                + '<dl class="rcard-kv mt-2">' + rows + '</dl>'
                + (result.enabled ? '' : '<div class="rcard-note"><i class="fas fa-circle-info" aria-hidden="true"></i><span>'
                    + <?= json_encode(h(__('The list is disabled, so MISP does not flag this value today.'))) ?> + '</span></div>');
        }).catch(function () {
            out.innerHTML = state('danger', 'xmark', <?= json_encode(h(__('The value could not be tested.'))) ?>);
        });
    });
}
</script>
