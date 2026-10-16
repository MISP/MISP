<?php
/**
 * One tab of a galaxy's full matrix, for the overview's matrix modal.
 *
 * $matrix as EventsController::viewEventGalaxyMatrix() builds it.
 */
echo $this->element('GalaxyMatrix/full', [
    'matrix' => $matrix,
    'lightIcon' => 'misp-icon misp-icon-attribute misp-simple',
]);
