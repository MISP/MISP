<?php
/**
 * Status card of the AI settings tab: the ai_connector module as seen from
 * this instance, computed by Module::aiStatus() when the tab loads.
 *
 * Params:
 *  - status  array from Module::aiStatus()
 */

$pill = function ($level, $label, $icon = null) {
    $icons = array(0 => 'circle-xmark', 1 => 'triangle-exclamation', 2 => 'circle-check', 3 => 'circle-info');
    return sprintf(
        '<span class="ss-prio ss-lvl-%d"><i class="fas fa-%s"></i>%s</span>',
        (int)$level,
        h($icon ?: $icons[$level]),
        h($label)
    );
};
$row = function ($label, $right) {
    printf(
        '<div class="dg-row"><span class="dg-row-label">%s</span><span class="ms-auto d-flex align-items-center gap-2 flex-wrap justify-content-end">%s</span></div>',
        h($label),
        $right
    );
};

if (!$status['enabled']) {
    $verdict = array('level' => 3, 'label' => __('Disabled'), 'accent' => '#6c757d');
} elseif (!$status['reachable']) {
    $verdict = array('level' => 0, 'label' => __('Unreachable'), 'accent' => '#dc3545');
} elseif (!$status['listed']) {
    $verdict = array('level' => 1, 'label' => __('Module missing'), 'accent' => '#fd7e14');
} else {
    $verdict = array('level' => 2, 'label' => __('Ready'), 'accent' => '#198754');
}
?>
<div class="card shadow-sm mb-3 ss-section dg-card" id="ai-status-card" style="--ss-accent: <?= h($verdict['accent']) ?>;">
    <div class="card-header ss-section-header" style="cursor:default;">
        <span class="ss-section-icon"><i class="fas fa-robot"></i></span>
        <div class="flex-grow-1">
            <div class="fw-semibold"><?= __('Module status') ?></div>
            <div class="text-muted" style="font-size:.78rem;"><?= __('The ai_connector module as seen from this instance, checked when this tab loads') ?></div>
        </div>
        <?= $pill($verdict['level'], $verdict['label']) ?>
    </div>
    <div class="card-body">
        <?php
        $row(__('AI services'), $status['enabled']
            ? $pill(2, __('Enabled'))
            : $pill(3, __('Disabled')) . '<span class="text-muted small">' . __('Set %s to true to check the module.', '<code>Plugin.AI_services_enable</code>') . '</span>');
        $row(__('Module server'), '<code>' . h($status['server']) . '</code>');
        if ($status['enabled']) {
            $row(__('Reachable'), $status['reachable']
                ? $pill(2, __('Yes'))
                : $pill(0, __('No')) . '<span class="text-danger small">' . h($status['error']) . '</span>');
        }
        if ($status['reachable']) {
            if ($status['listed']) {
                $module = $status['module'];
                $details = array();
                if (!empty($module['version'])) {
                    $details[] = __('version %s', h($module['version']));
                }
                if (!empty($module['description'])) {
                    $details[] = h($module['description']);
                }
                $row(__('ai_connector'), $pill(2, __('Listed')) . ($details ? '<span class="text-muted small">' . implode(' — ', $details) . '</span>' : ''));
            } else {
                $row(__('ai_connector'), $pill(1, __('Not listed'))
                    . '<span class="text-muted small">' . ($status['error'] ? h($status['error']) : __('The server answers, but does not offer the ai_connector module.')) . '</span>');
            }
        }
        // Test LLM: the module's ping use-case through the dry run (no
        // event). Click-only: a dead endpoint fails only after the module's
        // own request timeout, so it is never run when the tab loads.
        $canPing = $status['enabled'] && $status['listed'];
        $pingTimeout = (int)Configure::read('Plugin.AI_timeout') ?: 300;
        $row(__('LLM endpoint'), sprintf(
            '<button type="button" class="btn btn-sm %s" data-aiping-run%s><i class="fas fa-plug-circle-check me-1"></i>%s</button><span class="text-muted small">%s</span>',
            $canPing ? 'btn-outline-primary' : 'btn-outline-secondary',
            $canPing ? '' : ' disabled aria-disabled="true"',
            __('Test LLM'),
            $canPing
                ? __('Asks the module whether the endpoint serves the configured model; waits up to %s s.', $pingTimeout)
                : __('Available once the AI services are enabled and the ai_connector module is listed.')
        ));
        ?>
        <div class="d-none" data-aiping-result></div>
    </div>
</div>
<?php if ($canPing): ?>
<script>
(function () {
    const root = document.getElementById('ai-status-card');
    const button = root.querySelector('[data-aiping-run]');
    const result = root.querySelector('[data-aiping-result]');
    const L = <?= json_encode(array(
        'testing' => __('Testing…'),
        'test' => __('Test LLM'),
        'ok' => __('OK'),
        'failed' => __('The LLM test failed'),
        'endpoint' => __('Endpoint'),
        'model' => __('Model'),
        'latency' => __('Latency'),
        'models' => __('Models listed'),
        'tagSuggest' => __('Tag suggestion service'),
        'reachable' => __('reachable'),
        'unreachable' => __('not reachable'),
        'ms' => __('%s ms'),
    ), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }
    function pill(level, icon, text) {
        const span = el('span', 'ss-prio ss-lvl-' + level);
        span.appendChild(el('i', 'fas fa-' + icon));
        span.appendChild(document.createTextNode(text));
        return span;
    }
    function row(label, nodes) {
        const div = el('div', 'dg-row');
        div.appendChild(el('span', 'dg-row-label', label));
        const right = el('span', 'ms-auto d-flex align-items-center gap-2 flex-wrap justify-content-end');
        nodes.forEach(function (node) { right.appendChild(node); });
        div.appendChild(right);
        return div;
    }
    function asText(value) {
        return typeof value === 'string' ? value : JSON.stringify(value);
    }
    function render(r) {
        const model = r.model || {};
        const details = [model.server, model.digest, model.quantization].filter(Boolean).join(', ');
        result.replaceChildren();
        result.appendChild(row(L.endpoint, [pill(2, 'circle-check', L.ok), el('code', '', r.endpoint || '')]));
        result.appendChild(row(L.model, [el('span', 'fw-semibold', model.name || ''), el('span', 'text-muted small', details)]));
        if (r.latency_ms !== undefined) result.appendChild(row(L.latency, [el('span', '', L.ms.replace('%s', r.latency_ms))]));
        if (r.models_listed !== undefined) result.appendChild(row(L.models, [el('span', '', String(r.models_listed))]));
        if (r.tag_suggest) {
            const up = !!r.tag_suggest.reachable;
            result.appendChild(row(L.tagSuggest, [pill(up ? 2 : 0, up ? 'circle-check' : 'circle-xmark', up ? L.reachable : L.unreachable), el('code', '', r.tag_suggest.url || '')]));
        }
        result.classList.remove('d-none');
    }
    function fail(text) {
        result.replaceChildren(row(L.endpoint, [pill(0, 'circle-xmark', L.failed), el('span', 'text-danger small', asText(text))]));
        result.classList.remove('d-none');
        showToast(L.failed, 'danger');
    }
    button.addEventListener('click', async function () {
        button.disabled = true;
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>' + L.testing;
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
                body: JSON.stringify({use_case: 'ping'})
            });
            const data = await response.json();
            if (!response.ok || data.success !== true) {
                throw new Error(asText(data.errors || data.message || L.failed));
            }
            render(data.result || {});
        } catch (err) {
            fail(err.message);
        } finally {
            button.disabled = false;
            button.innerHTML = '<i class="fas fa-plug-circle-check me-1"></i>' + L.test;
        }
    });
})();
</script>
<?php endif; ?>
