<?php
$event = Hash::extract($row, $field['data_path']);

if (empty($event)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

$distributionPath = array_key_exists('distribution_path', $field)
    ? $field['distribution_path']
    : 'Event.distribution';
$publishedPath = array_key_exists('published_path', $field)
    ? $field['published_path']
    : 'Event.published';
?>

<div class="d-flex flex-column">
    <div class="d-flex align-items-center gap-2 flex-wrap mb-0">
        <?php if (!$isCard):
            if (!empty($distributionPath)) {
                echo $this->element(
                    '/genericElementsBS5/IndexTable/Fields/distribution',
                    [
                        'row' => $row,
                        'field' => [
                            'data_path' => $distributionPath,
                            'display' => 'short'
                        ]
                    ]
                );
            }
            if (!empty($publishedPath)) {
                echo $this->element(
                    '/genericElementsBS5/IndexTable/Fields/published',
                    [
                        'row' => $row,
                        'field' => ['data_path' => $publishedPath]
                    ]
                );
            }
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
