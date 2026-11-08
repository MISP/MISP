<?php
/**
 * The full comparison as a page of its own, for a link followed outside
 * the modal the view, the editor and the index open. Its value picker
 * reloads this page with `?value=`.
 *
 * @var array $base
 * @var array|null $in_force
 * @var string|null $focus
 */
echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'analyst-profile'),
    'js' => array('analyst-profile'),
));

$this->set('headerTitle', __('Full comparison'));
$this->set('headerIdentity', $base);
$this->set('headerDescription', h($focus === null
    ? sprintf(__('%1$s against %2$s'), $base['name'],
        $in_force === null ? __('nothing') : $in_force['name'])
    : sprintf(__('%1$s against %2$s, on %3$s'), $base['name'],
        $in_force === null ? __('nothing') : $in_force['name'], $focus)));
$this->set('headerActions', array(
    array(
        'type' => 'navigate',
        'label' => __('Back to the profile'),
        'icon' => 'arrow-left',
        'url' => $this->Html->url(array('action' => 'view', $base['id'],
            '?' => $focus === null ? array() : array('value' => $focus))),
    ),
));
?>
<div class="ap-page">
    <div class="container-fluid">
        <section class="card ap-vcard">
            <div class="ap-vcard-b">
                <?= $this->element('AnalystProfiles/compare_board', array(
                    'modal' => false,
                )) ?>
            </div>
        </section>
    </div>
</div>
