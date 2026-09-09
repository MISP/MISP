<?php
/*
 * AI tag recommendations for an event, rendered by
 * EventsController::aiRecommendTags() on GET and opened with
 * openGenericModal(). One row per suggested tag with a checkbox; the
 * accepted names are POSTed back to the same URL as a JSON list in the
 * form's `tags` field, and the tags and galaxies of the event view are
 * reloaded with the counts shown as a toast.
 *
 * Set by the controller:
 *   $event      array        the event (id, info)
 *   $rows       array        Event::classifyAiTagSuggestions() rows
 *   $local      bool         the tags will be attached as local tags
 *   $error      string|null  the module's error, when the query failed
 *   $canCreate  bool         the user may create unknown tags
 */
$eventId = (int)$event['Event']['id'];
$selectable = 0;
$needsEditor = false;
foreach ($rows as $row) {
    if ($row['selectable']) {
        $selectable++;
    }
    if ($row['status'] === Event::AI_TAG_NEEDS_TAG_EDITOR) {
        $needsEditor = true;
    }
}
?>
<div id="genericModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="genericModalLabel" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>
        <h3 id="genericModalLabel"><i class="fas fa-robot"></i> <?= __('Recommend tags with AI') ?></h3>
    </div>
    <div class="modal-body modal-body-long">
        <p><?= __('The AI module suggested the tags below for event #%s. Tick the ones to attach.', $eventId) ?></p>
        <?php if ($local): ?>
            <div class="alert alert-info"><?= __('You cannot modify this event: the accepted tags are attached as local tags.') ?></div>
        <?php endif; ?>
        <?php if ($needsEditor): ?>
            <div class="alert"><?= __('Some suggestions are tags unknown to this instance. Creating them needs the tag editor permission, so they cannot be selected.') ?></div>
        <?php endif; ?>
        <?php if ($error !== null): ?>
            <div class="alert alert-error"><?= h($error) ?></div>
        <?php elseif (empty($rows)): ?>
            <p class="muted"><?= __('The module suggested no tags for this event.') ?></p>
        <?php else: ?>
            <?php
            echo $this->Form->create('Event', [
                'url' => $baseurl . '/events/aiRecommendTags/' . $eventId,
                'id' => 'aiRecommendTagsForm',
                'class' => 'genericForm',
            ]);
            // A text input rather than a hidden one: the form token locks
            // the value of a hidden field, and this one is filled on submit.
            echo $this->Form->input('tags', [
                'label' => false,
                'div' => false,
                'type' => 'text',
                'id' => 'aiRecommendTagsField',
                'value' => '',
                'style' => 'display:none;',
            ]);
            echo $this->Form->end();
            ?>
            <table class="table table-striped table-condensed" id="aiRecommendTagsTable">
                <thead>
                    <tr>
                        <th style="width:30px;">
                            <input type="checkbox" id="aiRecommendTagsCheckAll" title="<?= __('Select all') ?>" <?= $selectable ? 'checked' : 'disabled' ?>>
                        </th>
                        <th><?= __('Tag') ?></th>
                        <th><?= __('Status') ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($rows as $row): ?>
                    <tr class="<?= $row['selectable'] ? '' : 'muted' ?>">
                        <td>
                            <input type="checkbox" class="aiRecommendTagCheck" data-name="<?= h($row['name']) ?>"
                                <?= $row['selectable'] ? 'checked' : 'disabled' ?>
                                aria-label="<?= h($row['name']) ?>">
                        </td>
                        <td>
                            <?= $this->element('tag', ['tag' => ['Tag' => ['name' => $row['name'], 'colour' => $row['colour']]]]) ?>
                        </td>
                        <td>
                            <?php if ($row['is_galaxy']): ?>
                                <span class="label"><i class="fas fa-atlas"></i> <?= __('galaxy cluster') ?></span>
                            <?php endif; ?>
                            <?php if (!$row['exists'] && $row['status'] !== Event::AI_TAG_PRESENT): ?>
                                <span class="label label-info"><?= __('new') ?></span>
                            <?php endif; ?>
                            <?php if ($row['reason'] !== ''): ?>
                                <span class="muted"><?= h($row['reason']) ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
    <div class="modal-footer">
        <?php if ($error === null && $selectable): ?>
            <span class="muted" style="float:left; line-height:30px;">
                <span id="aiRecommendTagsSelCount"><?= $selectable ?></span> / <?= $selectable ?> <?= __('selected') ?>
            </span>
            <button type="button" class="btn btn-primary" id="aiRecommendTagsSubmit" onclick="submitAiRecommendTags(<?= $eventId ?>);">
                <i class="fas fa-tags"></i> <?= __('Attach selected tags') ?>
            </button>
        <?php endif; ?>
        <button type="button" class="btn" data-dismiss="modal" aria-hidden="true"><?= __('Cancel') ?></button>
    </div>
</div>
<script type="text/javascript">
    (function () {
        var $checks = $('#aiRecommendTagsTable .aiRecommendTagCheck:not(:disabled)');
        var $all = $('#aiRecommendTagsCheckAll');
        function refreshCount() {
            var n = $checks.filter(':checked').length;
            $('#aiRecommendTagsSelCount').text(n);
            $('#aiRecommendTagsSubmit').prop('disabled', n === 0);
            $all.prop('checked', n === $checks.length);
        }
        $checks.on('change', refreshCount);
        $all.on('change', function () {
            $checks.prop('checked', $all.is(':checked'));
            refreshCount();
        });
        refreshCount();
    })();

    function submitAiRecommendTags(eventId) {
        var names = [];
        $('#aiRecommendTagsTable .aiRecommendTagCheck:checked').each(function () {
            names.push($(this).data('name'));
        });
        if (names.length === 0) {
            return;
        }
        $('#aiRecommendTagsField').val(JSON.stringify(names));
        $('#aiRecommendTagsSubmit').prop('disabled', true);
        var $form = $('#aiRecommendTagsForm');
        $.ajax({
            type: 'POST',
            url: $form.attr('action'),
            data: $form.serialize(),
            dataType: 'json',
            success: function (data) {
                $('#genericModal').modal('hide').remove();
                var message = data.success || data.message || data.errors || '<?= __('The tags could not be attached.') ?>';
                showMessage(data.saved ? 'success' : 'fail', message);
                if (data.attached > 0) {
                    loadEventTags(eventId);
                    loadGalaxies(eventId, 'event');
                }
                if (data.check_publish) {
                    checkAndSetPublishedInfo();
                }
            },
            error: function (xhr) {
                $('#aiRecommendTagsSubmit').prop('disabled', false);
                xhrFailCallback(xhr);
            }
        });
    }
</script>
