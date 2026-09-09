<?php
/**
 * Dry run box of the AI settings tab (legacy theme): send one event to the
 * ai_connector module and show its answer here. Nothing is written to the
 * event (D29). Same behaviour as the Overmind card.
 *
 * Params:
 *  - status  array from Module::aiStatus(), only `enabled` is read
 */

$enabled = !empty($status['enabled']);
$useCases = array(
    'summarization_on_event' => __('Summarise the event'),
    'tag_suggest' => __('Recommend tags'),
);
?>
<h3><?= __('Dry run') ?></h3>
<p><?= __('Send an event to the module and look at its answer. Nothing is written to the event.') ?></p>
<div class="diagnostics-box" id="aiDryRun">
    <form id="aiDryRunForm" style="margin:0;">
        <label for="aiDryRunEvent" style="display:inline-block; margin-right:1em;"><?= __('Event ID') ?>
            <input type="number" min="1" step="1" required id="aiDryRunEvent" class="input-small" <?= $enabled ? '' : 'disabled' ?>>
        </label>
        <label for="aiDryRunUseCase" style="display:inline-block; margin-right:1em;"><?= __('Action') ?>
            <select id="aiDryRunUseCase" class="input-large" <?= $enabled ? '' : 'disabled' ?>>
                <?php foreach ($useCases as $value => $label): ?>
                    <option value="<?= h($value) ?>"><?= h($label) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <button type="submit" class="btn btn-primary btn-small" id="aiDryRunButton" <?= $enabled ? '' : 'disabled' ?>>
            <i class="fas fa-robot"></i> <?= __('Run') ?>
        </button>
        <?php if (!$enabled): ?>
            <div style="color:#666666; margin-top:.5em;"><?= __('Enable the AI services above to run a dry run.') ?></div>
        <?php endif; ?>
    </form>
    <div id="aiDryRunResult" class="hidden" style="margin-top:1em;"></div>
</div>
<script type="text/javascript">
$(document).ready(function () {
    var L = <?= json_encode(array(
        'run' => __('Run'),
        'running' => __('Waiting for the module…'),
        'done' => __('The module answered.'),
        'failed' => __('The dry run failed'),
        'answered' => __('Answer for event %s'),
        'noTags' => __('The module recommended no tag.'),
        'newTag' => __('(new)'),
    ), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var $form = $('#aiDryRunForm');
    var $result = $('#aiDryRunResult');
    var $button = $('#aiDryRunButton');

    function asText(value) {
        return typeof value === 'string' ? value : JSON.stringify(value);
    }

    function render(data) {
        $result.empty();
        var head = L.answered.replace('%s', data.event_id);
        if (data.event_info) head += ' — ' + data.event_info;
        $result.append($('<div>').css({color: '#666666', marginBottom: '.5em'}).text(head));
        var answer = data.result || {};
        if (answer.EventReport) {
            $result.append($('<div>').css('font-weight', 'bold').text(answer.EventReport.name || ''));
            $result.append($('<pre>').css({whiteSpace: 'pre-wrap', maxHeight: '24em', overflow: 'auto'}).text(answer.EventReport.content || ''));
        } else if (answer.Tag) {
            if (!answer.Tag.length) $result.append($('<span>').css('color', '#666666').text(L.noTags));
            $.each(answer.Tag, function (i, tag) {
                $result.append($('<span>').addClass('tag').css({
                    display: 'inline-block', margin: '0 .4em .4em 0', padding: '.15em .5em', borderRadius: '.3em',
                    backgroundColor: tag.exists ? '#0088cc' : '#999999', color: '#ffffff'
                }).text(tag.name + (tag.exists ? '' : ' ' + L.newTag)));
            });
        } else {
            $result.append($('<pre>').text(JSON.stringify(answer, null, 2)));
        }
        $result.removeClass('hidden');
    }

    $form.on('submit', function (e) {
        e.preventDefault();
        $button.prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i> ' + L.running);
        $result.addClass('hidden');
        $.ajax({
            type: 'POST',
            url: baseurl + '/servers/aiDryRun',
            contentType: 'application/json',
            dataType: 'json',
            headers: {'X-CSRF-Token': (window.csrfToken || ''), 'Accept': 'application/json'},
            data: JSON.stringify({event_id: $('#aiDryRunEvent').val(), use_case: $('#aiDryRunUseCase').val()}),
            success: function (data) {
                if (!data || data.success !== true) {
                    showMessage('fail', L.failed + ': ' + asText((data && (data.errors || data.message)) || L.failed));
                    return;
                }
                render(data);
                showMessage('success', L.done);
            },
            error: function (xhr) {
                var body = xhr.responseJSON || {};
                showMessage('fail', L.failed + ': ' + asText(body.errors || body.message || xhr.statusText));
            },
            complete: function () {
                $button.prop('disabled', false).html('<i class="fas fa-robot"></i> ' + L.run);
            }
        });
    });
});
</script>
