<?php
/*
 * The template's attributes at a glance, in the order the object form offers
 * them. The full, sortable list stays in the Elements tab.
 */
$elements = $templateElements ?? [];
$requirements = $data['ObjectTemplate']['requirements'] ?? [];
$required = array_flip((array)($requirements['required'] ?? []));
$oneOf = array_flip((array)($requirements['requiredOneOf'] ?? []));
?>

<div class="card mb-3 shadow-sm" data-template-elements>
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="rounded-2 d-flex align-items-center justify-content-center"
                     style="width:36px;height:36px;background:rgba(var(--bs-object-rgb),.12);color:rgb(var(--bs-object-rgb));">
                    <i class="fas fa-cube"></i>
                </div>
                <div>
                    <div class="fw-bold lh-1"><?= __('Attributes') ?></div>
                    <div class="small text-muted mt-1">
                        <?= h(__n('%s attribute the object can hold', '%s attributes the object can hold', count($elements), count($elements))) ?>
                    </div>
                </div>
            </div>
            <a href="#tab-elements" class="btn btn-sm btn-outline-primary flex-shrink-0" data-te-tab
               title="<?= h(__('Open the full element index')) ?>">
                <i class="fas fa-list me-1"></i><?= __('Index') ?>
            </a>
        </div>
    </div>

    <?php if (empty($elements)): ?>
        <div class="card-body text-center text-body-secondary small py-4">
            <i class="fas fa-cube me-1 opacity-50"></i><?= __('This template defines no attribute.') ?>
        </div>
    <?php else: ?>
        <ul class="list-group list-group-flush overflow-auto" style="max-height:30rem;">
            <?php foreach ($elements as $element): ?>
                <?php
                $e = $element['ObjectTemplateElement'];
                $relation = (string)$e['object_relation'];
                ?>
                <li class="list-group-item d-flex align-items-center gap-3 py-2 px-3">
                    <div class="min-w-0 flex-grow-1 lh-sm">
                        <div class="d-flex flex-wrap align-items-center gap-2">
                            <span class="fw-semibold font-monospace text-break"><?= h($relation) ?></span>
                            <span class="badge rounded-pill fw-normal font-monospace"
                                  style="background:rgba(var(--bs-type-rgb),.12);color:rgb(var(--bs-type-rgb));"
                                  title="<?= h(__('Attribute type')) ?>"><?= h($e['type']) ?></span>
                        </div>
                        <?php if (trim((string)$e['description']) !== ''): ?>
                            <div class="small text-body-secondary text-truncate mt-1" title="<?= h($e['description']) ?>"><?= h($e['description']) ?></div>
                        <?php endif; ?>
                    </div>
                    <div class="d-flex flex-wrap justify-content-end gap-1 flex-shrink-0">
                        <?php if (isset($required[$relation])): ?>
                            <span class="badge rounded-pill bg-danger-subtle text-danger-emphasis border border-danger-subtle fw-normal"><?= __('Required') ?></span>
                        <?php elseif (isset($oneOf[$relation])): ?>
                            <span class="badge rounded-pill bg-warning-subtle text-warning-emphasis border border-warning-subtle fw-normal"
                                  title="<?= h(__('At least one of the attributes marked so must be filled')) ?>"><?= __('One of') ?></span>
                        <?php endif; ?>
                        <?php if (!empty($e['multiple'])): ?>
                            <span class="badge rounded-pill border bg-body-tertiary text-body-secondary fw-normal" title="<?= h(__('Can be repeated in one object')) ?>">
                                <i class="fas fa-clone me-1 opacity-50"></i><?= __('Multiple') ?>
                            </span>
                        <?php endif; ?>
                        <?php if (!empty($e['disable_correlation'])): ?>
                            <span class="badge rounded-pill border bg-body-tertiary text-body-secondary fw-normal" title="<?= h(__('Values are not correlated')) ?>">
                                <i class="fas fa-link-slash me-1 opacity-50"></i><?= __('No correlation') ?>
                            </span>
                        <?php endif; ?>
                    </div>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</div>

<script>
(function () {
    document.querySelectorAll('[data-template-elements] [data-te-tab]:not([data-te-bound])').forEach(function (link) {
        link.setAttribute('data-te-bound', '');
        link.addEventListener('click', function (event) {
            var tab = document.querySelector('.nav-link[href="#tab-elements"]');
            if (tab && window.bootstrap) {
                event.preventDefault();
                bootstrap.Tab.getOrCreateInstance(tab).show();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        });
    });
})();
</script>
