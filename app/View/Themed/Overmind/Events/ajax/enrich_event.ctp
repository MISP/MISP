<?php
/*
 * events/enrichEvent — pick the expansion modules to run over the whole event.
 *
 * Set by the controller:
 *   $modules  array  Module::getEnabledModules(…, 'expansion'), so
 *                    $modules['modules'] is a list of ['name' => …, …]
 */

$available = $modules['modules'] ?? [];
/* enrichEvent() passes only the module list, so the id comes from the URL. */
$eventId = $this->request->params['pass'][0] ?? ($id ?? null);

$uid = 'evt-enrich-' . dechex(mt_rand());
$hasModules = !empty($available);
/* Instances with a full misp-modules deployment list dozens of them. */
$filterable = count($available) > 8;

echo $this->Form->create('Event', [
    'id' => 'PromptForm',
    'url' => $this->request->here(false),
    'class' => 'm-0',
]);
?>
<div style="border-radius: var(--bs-modal-border-radius, var(--bs-border-radius-lg)); overflow: hidden;">
    <?= $this->element('genericElementsBS5/Forms/modal_header', [
        'accent' => 'enrichment',
        'eyebrow' => __('Event'),
        'title' => __('Enrich event'),
        'description' => __('Runs the selected expansion modules over the attributes of this event.'),
        'titleIcon' => 'fas fa-wand-magic-sparkles',
        'icon' => 'fas fa-wand-magic-sparkles',
    ]) ?>

    <div class="px-4 py-4 d-flex flex-column gap-3">
        <?php if (!$hasModules): ?>
            <p class="mb-0 lh-base text-body-secondary">
                <?= __('No expansion module is enabled on this instance, so there is nothing to run.') ?>
            </p>
        <?php else: ?>
            <div>
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'enrichment',
                    'label' => __('Expansion modules'),
                    'badge' => (string)count($available),
                ]) ?>

                <?php if ($filterable): ?>
                    <input type="text" class="form-control form-control-sm mb-2"
                           id="<?= h($uid) ?>-filter"
                           placeholder="<?= __('Filter modules…') ?>"
                           autocomplete="off">
                <?php endif; ?>

                <div class="border rounded-2 px-3 py-2"
                     id="<?= h($uid) ?>-list"
                     style="max-height:15rem; overflow-y:auto;">
                    <?php foreach ($available as $module): ?>
                        <div class="form-check mb-1 enrich-module"
                             data-name="<?= h(strtolower($module['name'])) ?>">
                            <?= $this->Form->checkbox($module['name'], [
                                'class' => 'form-check-input',
                                'id' => $uid . '-mod-' . h($module['name']),
                            ]) ?>
                            <label class="form-check-label" style="font-size:.85rem;"
                                   for="<?= h($uid . '-mod-' . $module['name']) ?>">
                                <?= h($module['name']) ?>
                            </label>
                        </div>
                    <?php endforeach; ?>
                    <div class="text-body-secondary fst-italic d-none"
                         id="<?= h($uid) ?>-empty" style="font-size:.8rem;">
                        <?= __('No module matches.') ?>
                    </div>
                </div>

                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => __('Enrichment runs as a background job; its results appear on the event once it completes.'),
                ]) ?>
            </div>
        <?php endif; ?>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'enrichment',
        'bleed' => true,
        'meta' => $eventId === null ? [] : [['label' => __('Event'), 'id' => $eventId]],
        'cancel' => ['label' => $hasModules ? __('Cancel') : __('Close'), 'icon' => 'fas fa-xmark'],
        'submit' => $hasModules
            ? [
                'label' => __('Enrich'),
                'icon' => 'fas fa-wand-magic-sparkles',
                'type' => 'submit',
                'id' => $uid . '-submit',
                // enrichmentRouter throws "modules not set" on an empty list
                'disabled' => true,
            ]
            : false,
    ]) ?>
</div>
<?= $this->Form->end() ?>

<?php if ($hasModules): ?>
<script>
(function () {
    var list = document.getElementById('<?= $uid ?>-list');
    var submit = document.getElementById('<?= $uid ?>-submit');
    if (!list) {
        return;
    }

    // Nothing checked is not a request the endpoint accepts.
    function syncSubmit() {
        if (submit) {
            submit.disabled = !list.querySelector('input[type=checkbox]:checked');
        }
    }
    list.addEventListener('change', syncSubmit);
    syncSubmit();

    var filter = document.getElementById('<?= $uid ?>-filter');
    var empty = document.getElementById('<?= $uid ?>-empty');
    if (!filter) {
        return;
    }
    filter.addEventListener('input', function () {
        var needle = filter.value.trim().toLowerCase();
        var shown = 0;
        list.querySelectorAll('.enrich-module').forEach(function (row) {
            var match = needle === '' || row.dataset.name.indexOf(needle) !== -1;
            // .d-none rather than style.display: the utility carries !important
            row.classList.toggle('d-none', !match);
            if (match) {
                shown++;
            }
        });
        if (empty) {
            empty.classList.toggle('d-none', shown !== 0);
        }
    });
})();
</script>
<?php endif; ?>
