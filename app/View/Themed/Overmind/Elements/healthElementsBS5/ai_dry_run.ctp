<?php
/**
 * Dry run card of the AI settings tab: send one event to the ai_connector
 * module and show its answer here. Nothing is written to the event (D29).
 *
 * Params:
 *  - status  array from Module::aiStatus(), only `enabled` is read
 */

$uid = 'aidr' . dechex(mt_rand());
$enabled = !empty($status['enabled']);
$useCases = array(
    'summarization_on_event' => __('Summarise the event'),
    'tag_suggest' => __('Recommend tags'),
);
?>
<div class="card shadow-sm mb-3 ss-section dg-card" id="<?= h($uid) ?>" style="--ss-accent: #20c997;">
    <div class="card-header ss-section-header" style="cursor:default;">
        <span class="ss-section-icon"><i class="fas fa-flask"></i></span>
        <div class="flex-grow-1">
            <div class="fw-semibold"><?= __('Dry run') ?></div>
            <div class="text-muted" style="font-size:.78rem;"><?= __('Send an event to the module and look at its answer. Nothing is written to the event.') ?></div>
        </div>
    </div>
    <div class="card-body">
        <form class="row g-2 align-items-end" data-aidr-form>
            <div class="col-sm-3">
                <label class="form-label small mb-1" for="<?= h($uid) ?>-event"><?= __('Event ID') ?></label>
                <input class="form-control form-control-sm" type="number" min="1" step="1" required
                       id="<?= h($uid) ?>-event" data-aidr-event <?= $enabled ? '' : 'disabled' ?>>
            </div>
            <div class="col-sm-4">
                <label class="form-label small mb-1" for="<?= h($uid) ?>-usecase"><?= __('Action') ?></label>
                <select class="form-select form-select-sm" id="<?= h($uid) ?>-usecase" data-aidr-usecase <?= $enabled ? '' : 'disabled' ?>>
                    <?php foreach ($useCases as $value => $label): ?>
                        <option value="<?= h($value) ?>"><?= h($label) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-sm-auto">
                <button type="submit" class="btn btn-sm btn-primary" data-aidr-run <?= $enabled ? '' : 'disabled' ?>>
                    <i class="fas fa-robot me-1"></i><?= __('Run') ?>
                </button>
            </div>
            <?php if (!$enabled): ?>
                <div class="col-12 text-muted small"><?= __('Enable the AI services above to run a dry run.') ?></div>
            <?php endif; ?>
        </form>
        <div class="mt-3 d-none" data-aidr-result></div>
    </div>
</div>
<script>
(function () {
    const root = document.getElementById('<?= h($uid) ?>');
    if (!root || root.dataset.aidrWired) return;
    root.dataset.aidrWired = '1';

    const L = <?= json_encode(array(
        'run' => __('Run'),
        'running' => __('Waiting for the module…'),
        'done' => __('The module answered.'),
        'failed' => __('The dry run failed'),
        'answered' => __('Answer for event %s'),
        'noTags' => __('The module recommended no tag.'),
        'newTag' => __('(new)'),
    ), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    const form = root.querySelector('[data-aidr-form]');
    const result = root.querySelector('[data-aidr-result]');
    const button = root.querySelector('[data-aidr-run]');

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    function asText(value) {
        return typeof value === 'string' ? value : JSON.stringify(value);
    }

    function render(data) {
        result.replaceChildren();
        let head = L.answered.replace('%s', data.event_id);
        if (data.event_info) head += ' — ' + data.event_info;
        result.appendChild(el('div', 'text-muted small mb-2', head));
        const answer = data.result || {};
        if (answer.EventReport) {
            result.appendChild(el('div', 'fw-semibold mb-1', answer.EventReport.name || ''));
            const pre = el('pre', 'border rounded p-2 mb-0', answer.EventReport.content || '');
            pre.style.whiteSpace = 'pre-wrap';
            pre.style.maxHeight = '24rem';
            pre.style.overflow = 'auto';
            result.appendChild(pre);
        } else if (answer.Tag) {
            const list = el('div', 'd-flex flex-wrap gap-2');
            if (!answer.Tag.length) list.appendChild(el('span', 'text-muted', L.noTags));
            answer.Tag.forEach(function (tag) {
                list.appendChild(el('span', 'badge ' + (tag.exists ? 'bg-primary' : 'bg-secondary'),
                    tag.name + (tag.exists ? '' : ' ' + L.newTag)));
            });
            result.appendChild(list);
        } else {
            result.appendChild(el('pre', 'border rounded p-2 mb-0', JSON.stringify(answer, null, 2)));
        }
        result.classList.remove('d-none');
    }

    form.addEventListener('submit', async function (event) {
        event.preventDefault();
        const payload = {
            event_id: root.querySelector('[data-aidr-event]').value,
            use_case: root.querySelector('[data-aidr-usecase]').value
        };
        button.disabled = true;
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>' + L.running;
        result.classList.add('d-none');
        try {
            const response = await fetch(baseurl + '/servers/aiDryRun', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': (window.csrfToken || '')
                },
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (!response.ok || data.success !== true) {
                throw new Error(asText(data.errors || data.message || L.failed));
            }
            render(data);
            showToast(L.done, 'success');
        } catch (err) {
            showToast(L.failed + ': ' + err.message, 'danger');
        } finally {
            button.disabled = false;
            button.innerHTML = '<i class="fas fa-robot me-1"></i>' + L.run;
        }
    });
})();
</script>
