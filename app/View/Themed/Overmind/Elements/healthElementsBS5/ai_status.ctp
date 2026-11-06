<?php
/**
 * Status card of the AI settings tab: the chain an AI action travels, one
 * step per link — MISP's switch, the module server, the ai_connector module,
 * the LLM endpoint. A step is only checked once the one before it holds, and
 * the first one that does not says how to fix it. The first three come from
 * Module::aiStatus() when the tab loads; the LLM is tested on demand only.
 *
 * Params:
 *  - status  array from Module::aiStatus()
 */

$code = function ($text) {
    return '<code>' . h($text) . '</code>';
};
$pill = function ($level, $label) {
    $icons = array(0 => 'circle-xmark', 1 => 'triangle-exclamation', 2 => 'circle-check', 3 => 'circle-info');
    return sprintf('<span class="ss-prio ss-lvl-%d"><i class="fas fa-%s"></i>%s</span>', (int)$level, $icons[$level], h($label));
};
$guideButton = function ($tab, $label, $icon, $class = 'btn-outline-primary') use ($baseurl) {
    $url = $baseurl . '/servers/aiConnectorGuide' . ($tab ? '/' . $tab : '');
    return sprintf(
        '<button type="button" class="btn btn-sm %s" onclick="%s"><i class="fas fa-%s me-1"></i>%s</button>',
        $class,
        h('openModal(' . json_encode($url) . ', \'xl\')'),
        $icon,
        h($label)
    );
};

$enabled = $status['enabled'];
$reachable = $status['reachable'];
$listed = $status['listed'];
$module = $status['module'];
$llm = $status['llm'];
$pingTimeout = (int)Configure::read('Plugin.AI_timeout') ?: 300;

if (!$enabled) {
    $verdict = array('level' => 3, 'label' => __('Disabled'), 'accent' => '#6c757d');
} elseif (!$reachable) {
    $verdict = array('level' => 0, 'label' => __('Unreachable'), 'accent' => '#dc3545');
} elseif (!$listed) {
    $verdict = array('level' => 1, 'label' => __('Module missing'), 'accent' => '#fd7e14');
} else {
    $verdict = array('level' => 2, 'label' => __('Ready'), 'accent' => '#198754');
}

/*
 * state: ok | fail | warn | off — checked; wait — not checked, a step above
 * fails; idle — checked on demand only.
 */
$moduleDetails = array();
if (!empty($module['version'])) {
    $moduleDetails[] = __('version %s', h($module['version']));
}
if (!empty($module['description'])) {
    $moduleDetails[] = h($module['description']);
}
$steps = array(
    array(
        'title' => __('AI services enabled'),
        'detail' => __('Setting %s', $code('Plugin.AI_services_enable')),
        'state' => $enabled ? 'ok' : 'off',
        'pill' => $enabled ? $pill(2, __('Enabled')) : $pill(3, __('Disabled')),
        'fix' => $enabled ? null : array(
            'level' => 3,
            'text' => __('MISP does not contact the module, and offers no AI action anywhere. Install the module first, then set %s to true in the settings below.', $code('Plugin.AI_services_enable')),
            'buttons' => $guideButton(null, __('Installation guide'), 'book-open', 'btn-primary'),
        ),
    ),
    array(
        'title' => __('Module server reachable'),
        'detail' => __('%s, from %s and %s', $code($status['server']), $code('Plugin.AI_services_url'), $code('Plugin.AI_services_port')),
        'state' => !$enabled ? 'wait' : ($reachable ? 'ok' : 'fail'),
        'pill' => !$enabled ? $pill(3, __('Not checked')) : ($reachable ? $pill(2, __('Answering')) : $pill(0, __('Unreachable'))),
        'fix' => !$enabled || $reachable ? null : array(
            'level' => 0,
            'error' => $status['error'],
            'text' => __('MISP cannot open a connection to this address. Check that the module server runs, and that the URL and port point at it: ai_connector has a misp-modules server of its own, on port 6667 by default. In Docker, the URL is the service name, e.g. %s.', $code('http://ai-connector')),
            'buttons' => $guideButton(null, __('Installation guide'), 'book-open') . $guideButton('troubleshooting', __('Troubleshooting'), 'stethoscope', 'btn-outline-secondary'),
        ),
    ),
    array(
        'title' => __('ai_connector module loaded'),
        'detail' => $listed && $moduleDetails
            ? implode(' — ', $moduleDetails)
            : __('The module that carries out the AI actions, served by the server above.'),
        'state' => !$reachable ? 'wait' : ($listed ? 'ok' : 'warn'),
        'pill' => !$reachable ? $pill(3, __('Not checked')) : ($listed ? $pill(2, __('Loaded')) : $pill(1, __('Not offered'))),
        'fix' => !$reachable || $listed ? null : array(
            'level' => 1,
            'error' => $status['error'],
            'text' => __('A server answers, but it does not offer ai_connector. On port 6666 you are reaching the enrichment server; otherwise the module failed to load, and the server\'s logs say why.'),
            'buttons' => $guideButton('troubleshooting', __('Troubleshooting'), 'stethoscope'),
        ),
    ),
    array(
        'title' => __('LLM endpoint answers'),
        'detail' => __('%s, model %s', $code($llm['endpoint'] !== '' ? $llm['endpoint'] : '—'), $code($llm['model'] !== '' ? $llm['model'] : '—')),
        'state' => $listed ? 'idle' : 'wait',
        'pill' => $listed
            ? sprintf(
                '<button type="button" class="btn btn-sm btn-outline-primary" data-aiping-run title="%s"><i class="fas fa-plug-circle-check me-1"></i>%s</button>',
                h(__('Asks the module whether the endpoint serves the configured model; waits up to %s s.', $pingTimeout)),
                h(__('Test LLM'))
            )
            : $pill(3, __('Not checked')),
        'llm' => true,
    ),
);
$glyphs = array('ok' => 'check', 'fail' => 'xmark', 'warn' => 'exclamation', 'off' => 'power-off');
?>
<div class="card shadow-sm mb-3 ss-section dg-card dg-scope" id="ai-status-card" style="--ss-accent: <?= h($verdict['accent']) ?>;">
    <div class="card-header ss-section-header flex-wrap" style="cursor:default;">
        <span class="ss-section-icon"><i class="fas fa-robot"></i></span>
        <div class="flex-grow-1">
            <div class="fw-semibold"><?= __('Module status') ?></div>
            <div class="text-muted" style="font-size:.78rem;"><?= __('Each link an AI action goes through, checked in order when this tab loads. The LLM is only tested on request.') ?></div>
        </div>
        <div class="d-flex align-items-center gap-2">
            <?= $pill($verdict['level'], $verdict['label']) ?>
            <?= $guideButton(null, __('Installation guide'), 'book-open', 'btn-outline-primary') ?>
        </div>
    </div>
    <div class="card-body">
        <ol class="aic-chain">
            <?php foreach ($steps as $i => $step): ?>
                <li class="aic-step aic-step-<?= h($step['state']) ?>"<?= empty($step['llm']) ? '' : ' data-aiping-step' ?>>
                    <span class="aic-dot" aria-hidden="true" data-aic-dot><?= isset($glyphs[$step['state']])
                        ? '<i class="fas fa-' . $glyphs[$step['state']] . '"></i>'
                        : $i + 1 ?></span>
                    <div class="aic-step-body">
                        <div class="d-flex align-items-center flex-wrap gap-2">
                            <span class="fw-semibold"><?= h($step['title']) ?></span>
                            <span class="ms-auto d-flex align-items-center gap-2" data-aic-status><?= $step['pill'] ?></span>
                        </div>
                        <div class="aic-step-detail"><?= $step['detail'] ?></div>
                        <?php if (!empty($step['fix'])): ?>
                            <div class="aic-fix aic-fix-<?= (int)$step['fix']['level'] ?>">
                                <?php if (!empty($step['fix']['error'])): ?>
                                    <div class="aic-fix-error"><?= h($step['fix']['error']) ?></div>
                                <?php endif; ?>
                                <div><?= $step['fix']['text'] ?></div>
                                <div class="d-flex flex-wrap gap-2 mt-2"><?= $step['fix']['buttons'] ?></div>
                            </div>
                        <?php endif; ?>
                        <?php if (!empty($step['llm'])): ?>
                            <div class="d-none" data-aiping-result></div>
                        <?php endif; ?>
                    </div>
                </li>
            <?php endforeach; ?>
        </ol>
    </div>
</div>
<?php if ($listed): ?>
<script>
(function () {
    const root = document.getElementById('ai-status-card');
    const step = root.querySelector('[data-aiping-step]');
    const button = step.querySelector('[data-aiping-run]');
    const dot = step.querySelector('[data-aic-dot]');
    const result = step.querySelector('[data-aiping-result]');
    const L = <?= json_encode(array(
        'testing' => __('Testing…'),
        'test' => __('Test LLM'),
        'retest' => __('Test again'),
        'ok' => __('OK'),
        'failed' => __('The LLM test failed'),
        'failedHelp' => __('The module answers, but it got no answer from the LLM. The endpoint must be reachable from the module\'s host, not from MISP\'s, and serve the model exactly as named.'),
        'troubleshooting' => __('Troubleshooting'),
        'model' => __('Model'),
        'latency' => __('Latency'),
        'models' => __('Models listed'),
        'tagSuggest' => __('Tag suggestion service'),
        'reachable' => __('reachable'),
        'unreachable' => __('not reachable'),
        'ms' => __('%s ms'),
    ), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    const guideUrl = <?= json_encode($baseurl . '/servers/aiConnectorGuide/troubleshooting') ?>;

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
    function setState(state, glyph, badge) {
        step.className = 'aic-step aic-step-' + state;
        dot.replaceChildren(el('i', 'fas fa-' + glyph));
        const status = step.querySelector('[data-aic-status]');
        status.replaceChildren();
        if (badge) status.appendChild(badge);
        status.appendChild(button);
    }
    function render(r) {
        const model = r.model || {};
        const details = [model.server, model.digest, model.quantization].filter(Boolean).join(', ');
        setState('ok', 'check', pill(2, 'circle-check', L.ok));
        result.className = 'aic-result';
        result.replaceChildren();
        if (model.name) result.appendChild(row(L.model, [el('span', 'fw-semibold', model.name), el('span', 'text-muted small', details)]));
        if (r.latency_ms !== undefined) result.appendChild(row(L.latency, [el('span', '', L.ms.replace('%s', r.latency_ms))]));
        if (r.models_listed !== undefined) result.appendChild(row(L.models, [el('span', '', String(r.models_listed))]));
        if (r.tag_suggest) {
            const up = !!r.tag_suggest.reachable;
            result.appendChild(row(L.tagSuggest, [pill(up ? 2 : 1, up ? 'circle-check' : 'triangle-exclamation', up ? L.reachable : L.unreachable), el('code', '', r.tag_suggest.url || '')]));
        }
    }
    function fail(text) {
        setState('fail', 'xmark', pill(0, 'circle-xmark', L.failed));
        const help = el('button', 'btn btn-sm btn-outline-primary mt-2');
        help.type = 'button';
        help.appendChild(el('i', 'fas fa-stethoscope me-1'));
        help.appendChild(document.createTextNode(L.troubleshooting));
        help.addEventListener('click', function () { openModal(guideUrl, 'xl'); });
        result.className = 'aic-fix aic-fix-0';
        result.replaceChildren(el('div', 'aic-fix-error', asText(text)), el('div', '', L.failedHelp), help);
        showToast(L.failed, 'danger');
    }
    button.addEventListener('click', async function () {
        button.disabled = true;
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>' + L.testing;
        result.className = 'd-none';
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
            button.innerHTML = '<i class="fas fa-rotate-right me-1"></i>' + L.retest;
        }
    });
})();
</script>
<?php endif; ?>
