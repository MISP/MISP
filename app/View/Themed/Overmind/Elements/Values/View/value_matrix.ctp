<?php
/**
 * The Overview rail's galaxy matrix: the event page's card, read off the
 * value's occurrences and the events holding it. Nothing when it carries no
 * matrix technique.
 *
 * Lazily loaded into `.ajax-card` from ValuesController::viewMatrix;
 * misp-matrix.js mounts it on arrival.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
$matrix = $valueIntelligence['matrix'];
if (empty($matrix['galaxies'])) {
    return;
}
?>
<div data-mx-slot>
    <?= $this->element('GalaxyMatrix/card', array(
        'matrix' => $matrix,
        'texts' => array(
            'onEvent' => __('On the value'),
            'onlyOne' => __('Only on 1 event holding it'),
            'onlyMany' => __('Only on %s events holding it'),
            'onOne' => __('On 1 event holding it'),
            'onMany' => __('On %s events holding it'),
        ),
        'fullUrl' => $baseurl . '/values/viewGalaxyMatrix/' . $valueB64
            . '/%s',
        'lightIcon' => 'misp-icon misp-icon-event misp-simple',
    )) ?>
</div>
<?= $this->element('GalaxyMatrix/modal', array(
    'strongLabel' => __('On the value'),
    'lightLabel' => __('Only on its events'),
)) ?>
