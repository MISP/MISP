<?php
/**
 * Status of the ai_connector module on the AI settings tab (legacy theme),
 * computed by Module::aiStatus() when the tab loads. Same content as the
 * Overmind card, in the diagnostics-box style of this theme.
 *
 * Params:
 *  - status  array from Module::aiStatus()
 */

$colours = array('green' => '#009933', 'orange' => '#e68a00', 'red' => '#cc0000', 'grey' => '#666666');
$span = function ($colour, $text) use ($colours) {
    return sprintf('<span style="color:%s;">%s</span>', $colours[$colour], h($text));
};

if (!$status['enabled']) {
    $verdict = $span('grey', __('Disabled'));
} elseif (!$status['reachable']) {
    $verdict = $span('red', __('Unreachable'));
} elseif (!$status['listed']) {
    $verdict = $span('orange', __('Module missing'));
} else {
    $verdict = $span('green', __('Ready'));
}
?>
<h3><?= __('Module status') ?>…<?= $verdict ?></h3>
<p><?= __('The ai_connector module as seen from this instance, checked when this tab loads.') ?></p>
<div class="diagnostics-box">
    <?= __('AI services') ?>…<?= $status['enabled'] ? $span('green', __('Enabled')) : $span('grey', __('Disabled')) ?>
    <?php if (!$status['enabled']): ?>
        <span style="color:<?= $colours['grey'] ?>;"><?= __('Set %s to true to check the module.', '<code>Plugin.AI_services_enable</code>') ?></span>
    <?php endif; ?>
    <br>
    <?= __('Module server') ?>…<code><?= h($status['server']) ?></code><br>
    <?php if ($status['enabled']): ?>
        <?= __('Reachable') ?>…<?= $status['reachable'] ? $span('green', __('OK')) : $span('red', $status['error']) ?><br>
    <?php endif; ?>
    <?php if ($status['reachable']): ?>
        <?php if ($status['listed']): ?>
            <?php
            $details = array();
            if (!empty($status['module']['version'])) {
                $details[] = __('version %s', $status['module']['version']);
            }
            if (!empty($status['module']['description'])) {
                $details[] = $status['module']['description'];
            }
            ?>
            ai_connector…<?= $span('green', __('Listed')) ?><?= $details ? ' ' . $span('grey', implode(' — ', $details)) : '' ?><br>
        <?php else: ?>
            ai_connector…<?= $span('orange', __('Not listed')) ?> <?= $span('grey', $status['error'] ?: __('The server answers, but does not offer the ai_connector module.')) ?><br>
        <?php endif; ?>
    <?php endif; ?>
    <?php
    // Test LLM: the module's ping use-case through the dry run (no event).
    // Click-only: a dead endpoint fails only after the module's own request
    // timeout, so it is never run when the tab loads.
    $canPing = $status['enabled'] && $status['listed'];
    $pingTimeout = (int)Configure::read('Plugin.AI_timeout') ?: 300;
    ?>
    <?= __('LLM endpoint') ?>…<button type="button" class="btn btn-small" id="aiPingButton" <?= $canPing ? '' : 'disabled' ?>><i class="fas fa-plug"></i> <?= __('Test LLM') ?></button>
    <?php if ($canPing): ?>
        <?= $span('grey', __('Asks the module whether the endpoint serves the configured model; waits up to %s s.', $pingTimeout)) ?>
    <?php else: ?>
        <?= $span('grey', __('Available once the AI services are enabled and the ai_connector module is listed.')) ?>
    <?php endif; ?>
    <br>
    <div id="aiPingResult" class="hidden" style="margin-top:.5em;"></div>
</div>
<?php if ($canPing): ?>
<script type="text/javascript">
$(document).ready(function () {
    var L = <?= json_encode(array(
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
    var $button = $('#aiPingButton');
    var $result = $('#aiPingResult');
    function coloured(colour, text) {
        return $('<span>').css('color', colour).text(text);
    }
    function row(label, $value) {
        return $('<div>').append(document.createTextNode(label + '… ')).append($value);
    }
    function asText(value) {
        return typeof value === 'string' ? value : JSON.stringify(value);
    }
    function render(r) {
        var model = r.model || {};
        var details = [model.server, model.digest, model.quantization].filter(Boolean).join(', ');
        $result.empty();
        $result.append(row(L.endpoint, coloured('#009933', L.ok + ' ' + (r.endpoint || ''))));
        $result.append(row(L.model, $('<span>').text((model.name || '') + (details ? ' (' + details + ')' : ''))));
        if (r.latency_ms !== undefined) $result.append(row(L.latency, $('<span>').text(L.ms.replace('%s', r.latency_ms))));
        if (r.models_listed !== undefined) $result.append(row(L.models, $('<span>').text(r.models_listed)));
        if (r.tag_suggest) {
            var up = !!r.tag_suggest.reachable;
            $result.append(row(L.tagSuggest, coloured(up ? '#009933' : '#cc0000', (up ? L.reachable : L.unreachable) + ' ' + (r.tag_suggest.url || ''))));
        }
        $result.removeClass('hidden');
    }
    function fail(text) {
        $result.empty().append(row(L.endpoint, coloured('#cc0000', asText(text)))).removeClass('hidden');
        showMessage('fail', L.failed);
    }
    $button.on('click', function () {
        $button.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> ' + L.testing);
        $result.addClass('hidden');
        $.ajax({
            type: 'POST',
            url: baseurl + '/servers/aiDryRun',
            contentType: 'application/json',
            dataType: 'json',
            headers: {'X-CSRF-Token': (window.csrfToken || ''), 'Accept': 'application/json'},
            data: JSON.stringify({use_case: 'ping'}),
            success: function (data) {
                if (!data || data.success !== true) {
                    fail((data && (data.errors || data.message)) || L.failed);
                    return;
                }
                render(data.result || {});
            },
            error: function (xhr) {
                var body = xhr.responseJSON || {};
                fail(body.errors || body.message || xhr.statusText);
            },
            complete: function () {
                $button.prop('disabled', false).html('<i class="fas fa-plug"></i> ' + L.test);
            }
        });
    });
});
</script>
<?php endif; ?>
