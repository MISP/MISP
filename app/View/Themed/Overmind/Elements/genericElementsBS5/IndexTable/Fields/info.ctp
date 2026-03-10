<?php
$event = Hash::extract($row, $field['data_path']);

if (empty($event)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';
?>

<div class="d-flex flex-column">
    <div class="d-flex align-items-baseline gap-2 mb-0">
        <?php if (!$isCard) {
                echo $this->element(
                    '/genericElementsBS5/IndexTable/Fields/distribution',
                    [
                        'row' => $row,
                        'field' => [
                            'data_path' => 'Event.distribution',
                            'display' =>'short'
                        ]
                    ]
                );
            }
        ?>
        <p class="mb-0">
            <?= h($event['info']); ?>
    </p>

    </div>

    <!-- Show if it extends an other Event -->
    <?php if (!empty($event['extends_uuid'])): ?>
        <div class="text-muted small mt-1 ms-3">
            Extends:
            <?php foreach ($extendedEvents as $extendedEvent): ?>
                <?php if ($extendedEvent['uuid'] === $event['extends_uuid']): ?>
                    <a href="/events/view/<?= h($extendedEvent['uuid']); ?>" class="text-decoration-none text-primary">
                        <?= h($extendedEvent['info']); ?>
                    </a>
                    <?php break; ?>
                <?php endif; ?>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

</div>