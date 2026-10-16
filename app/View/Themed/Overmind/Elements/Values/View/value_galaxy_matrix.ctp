<?php
/**
 * One tab of a galaxy's full matrix, for the matrix card's modal.
 *
 * Served by ValuesController::viewGalaxyMatrix.
 *
 * @var array $valueIntelligence
 */
echo $this->element('GalaxyMatrix/full', array(
    'matrix' => $valueIntelligence['matrix'],
    'lightIcon' => 'misp-icon misp-icon-event misp-simple',
));
