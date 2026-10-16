<?php
/**
 * The words js/tile-drawer.js puts on screen, as the JSON a host carries
 * in `data-td-strings`. Escape it for the attribute where it is printed.
 *
 * @var array $extra the host's own strings, merged in
 */
echo json_encode(array_merge(array(
    'previous' => __('Previous: %s'),
    'next' => __('Next: %s'),
    'noPrevious' => __('No previous tile'),
    'noNext' => __('No next tile'),
    'neighbours' => __('Neighbouring tiles'),
    'showAll' => __('Show all %s'),
    'showFewer' => __('Show fewer'),
    'rows' => __('%1$s of %2$s rows'),
    'allRows' => __('All %s rows'),
), isset($extra) ? $extra : array()));
