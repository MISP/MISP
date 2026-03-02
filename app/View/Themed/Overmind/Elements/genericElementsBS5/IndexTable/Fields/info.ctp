<?php
$event = Hash::extract($row, $field['data_path']);

if (empty($event)) {
    return;
}

$distribution = $event['distribution']

?>


<!-- Ligne principale : Badge + Nom -->
<div class="d-flex align-items-baseline gap-2 mb-0">

    <!-- Badge distribution -->
    <?php
        if ($distribution !== null) {
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

    <!-- Nom de l'event -->
    <p class="mb-0">
        <?= h($event['info']); ?>
</p>

</div>

<!-- Extends / Extended -->
<?php if (!empty($event['Event']['extends_uuid'])): ?>
    <div class="text-muted small mt-1">
        Extends:
        <a href="/events/view/<?= h($event['Event']['extends_uuid']); ?>" class="text-decoration-none">
            <?= h($event['extends_event_info']); ?>
        </a>
    </div>
<?php endif; ?>

<?php if (!empty($event['extended_by_uuid'])): ?>
    <div class="text-muted small mt-1">
        Extended:
        <a href="/events/view/<?= h($event['Event']['extended_by_uuid']); ?>" class="text-decoration-none">
            <?= h($event['Event']['extended_event_info']); ?>
        </a>
    </div>
<?php endif; ?>



