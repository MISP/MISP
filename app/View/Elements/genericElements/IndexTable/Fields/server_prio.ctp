<?php
$serverId = $row['Server']['id'];

foreach (['up', 'down'] as $direction) {
    echo sprintf(
        '<i class="fas fa-arrow-circle-%s rearrange-%s useCursorPointer"
            aria-label="%s"
            title="%s"
            data-server-id="%s"></i>',
        h($direction),
        h($direction),
        $direction === 'up' ? __('Move server priority up') : __('Move server priority down'),
        $direction === 'up' ? __('Move server priority up') : __('Move server priority down'),
        h($serverId)
    );
}
