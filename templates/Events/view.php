<h2 class="fw-light text-truncate"><?= h($entity['Event']['info']) ?></h2>

<div class="mb-2">
    <?= $this->element('Events/event-critical-notices') ?>
</div>

<div class="d-flex flex-row gap-2 mb-3">
    <div style="flex-basis: 33%;">
        <?= $this->element('Events/event-metadata') ?>
    </div>
    <div class="flex-grow-1">
        <?= $this->element('Events/event-context') ?>
    </div>
</div>

<div class="mb-3">
    <?= $this->element('Events/event-stats') ?>
</div>

<div class="mb-2">
    <?= $this->element('Events/event-notices') ?>
</div>

<div class="mb-2">
    <?= $this->element('Events/event-content') ?>
</div>