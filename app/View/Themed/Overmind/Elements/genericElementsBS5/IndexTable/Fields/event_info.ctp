<?php
$event = Hash::extract($row, $field['data_path']);

if (empty($event)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';
?>

<div class="d-flex flex-column">
    <div class="d-flex align-items-center gap-2 flex-wrap mb-0">
        <?php if (!$isCard):
            echo $this->element(
                '/genericElementsBS5/IndexTable/Fields/distribution',
                [
                    'row' => $row,
                    'field' => [
                        'data_path' => 'Event.distribution',
                        'display' => 'short'
                    ]
                ]
            );
            echo $this->element(
                '/genericElementsBS5/IndexTable/Fields/published',
                [
                    'row' => $row,
                    'field' => ['data_path' => 'Event.published']
                ]
            );
        endif; ?>

        <p class="mb-0 fw-semibold" style ="font-size: 1.2em;">
            <?= h($event['info']); ?>
        </p>
    </div>

    <?php if (!empty($event['extends_uuid'])): ?>
        <div class="text-muted small mt-1 ms-3">
            Extends:
            <?php foreach ($extendedEvents as $extendedEvent): ?>
                <?php if ($extendedEvent['uuid'] === $event['extends_uuid']): ?>
                    <a href="/events/view/<?= h($extendedEvent['uuid']); ?>"
                       class="text-decoration-none text-primary">
                        <?= h($extendedEvent['info']); ?>
                    </a>
                    <?php break; ?>
                <?php endif; ?>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>
