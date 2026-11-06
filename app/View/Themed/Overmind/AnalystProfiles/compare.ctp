<?php
/**
 * The full comparison as the content of #mainModal: what the view, the
 * editor and the index open instead of leaving for the simulate page.
 * The editor posts its unsaved form here, so the candidate is what is
 * being typed rather than what was last saved.
 *
 * @var array $base
 * @var array|null $in_force
 * @var string|null $focus
 */
echo $this->element('genericElementsBS5/Forms/modal_header', array(
    'eyebrow' => __('Analyst Profiles'),
    'title' => __('Full comparison'),
    'description' => $focus === null
        ? sprintf(__('%1$s against %2$s'), $base['name'],
            $in_force === null ? __('nothing') : $in_force['name'])
        : sprintf(__('%1$s against %2$s, on %3$s'), $base['name'],
            $in_force === null ? __('nothing') : $in_force['name'], $focus),
    'titleIcon' => 'fas fa-flask',
    'icon' => 'fas fa-flask',
    'accent' => 'primary',
));
?>
<div class="px-4 py-3">
    <?= $this->element('AnalystProfiles/compare_board', array('modal' => true)) ?>
</div>
<?= $this->element('genericElementsBS5/Forms/modal_footer', array(
    'accent' => 'primary',
    'bleed' => true,
    'align' => 'between',
    'hint' => __('It computes; it writes nothing.'),
    'cancel' => array('label' => __('Close'), 'icon' => 'fas fa-xmark'),
    'submit' => false,
)) ?>
