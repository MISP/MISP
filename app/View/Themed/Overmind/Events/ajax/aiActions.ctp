<?php
/*
 * Chooser of the AI actions on an event, opened in the main modal from the
 * event actions menu (EventsController::aiActions). Each entry loads the
 * confirmation of the action into the same modal.
 *
 * Set by the controller:
 *   $event    array  the event (id, info)
 *   $actions  array  entries with url, icon, text, description
 */
?>
<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'primary',
    'eyebrow' => __('AI actions'),
    'title' => __('Choose an action'),
    'titleIcon' => 'fas fa-robot',
    'icon' => 'fas fa-robot',
    'description' => __('Event #%s — the AI module runs the chosen action; you confirm it next.', h($event['Event']['id'])),
    'close' => true,
]) ?>

<div class="p-4" style="background:var(--bs-tertiary-bg, #f8f9fa);">
    <div class="d-flex flex-column gap-2">
        <?php foreach ($actions as $action): ?>
            <button type="button"
                    class="btn btn-light border text-start d-flex align-items-start gap-3 p-3 ai-action-choice"
                    data-url="<?= h($action['url']) ?>">
                <span class="d-inline-flex align-items-center justify-content-center rounded-circle flex-shrink-0"
                      style="width:2.2rem;height:2.2rem;background:rgba(13,110,253,.1);">
                    <i class="<?= h($action['icon']) ?> text-primary"></i>
                </span>
                <span class="flex-grow-1">
                    <span class="fw-bold d-block"><?= h($action['text']) ?></span>
                    <span class="text-muted small"><?= h($action['description']) ?></span>
                </span>
                <i class="fas fa-chevron-right text-muted align-self-center"></i>
            </button>
        <?php endforeach; ?>
    </div>
</div>

<script>
(function () {
    var body = document.getElementById('mainModalBody');
    if (!body) { return; }
    body.querySelectorAll('.ai-action-choice').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var url = btn.getAttribute('data-url');
            if (url) { openModal(url, 'md'); }
        });
    });
})();
</script>
