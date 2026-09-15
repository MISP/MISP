<?php
/*
 * Chooser of the AI actions on an event, loaded into #confirmation_box from
 * the event side menu (EventsController::aiActions). Each entry closes this
 * chooser and opens the confirmation of the action in the generic modal.
 *
 * Set by the controller:
 *   $event    array  the event (id, info)
 *   $actions  array  entries with url, icon, text, description
 */
?>
<div class="confirmation">
    <legend><?= __('AI actions') ?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <p><?= __('Event #%s — choose what the AI module should do. You confirm the action next.', h($event['Event']['id'])) ?></p>
        <?php foreach ($actions as $action): ?>
            <button type="button" class="btn btn-primary"
                    style="display:block; width:100%; margin-bottom:6px; text-align:left; white-space:normal;"
                    onclick="cancelPrompt(); openGenericModal('<?= h($action['url']) ?>');"
                    title="<?= h($action['description']) ?>">
                <i class="<?= h($action['icon']) ?>"></i> <?= h($action['text']) ?>
                <span style="display:block; font-size:.85em; opacity:.85;"><?= h($action['description']) ?></span>
            </button>
        <?php endforeach; ?>
        <span role="button" tabindex="0" aria-label="<?= __('Cancel') ?>" title="<?= __('Cancel') ?>" class="btn btn-inverse" onclick="cancelPrompt();"><?= __('Cancel') ?></span>
    </div>
</div>
