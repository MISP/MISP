<?php
/**
 * The editor's action card, in the view's frame: save the form, go back
 * to the profile, compare on a value, export.
 *
 * @var array $profile
 * @var array $bench
 */
$focus = $bench['focus'];
$query = $focus === null ? array() : array('value' => $focus);

echo $this->element('genericElementsBS5/Cards/card_launch_bar', array(
    'actions' => array(
        array(
            'url' => '#',
            'onclick' => 'event.preventDefault(); analystProfileSave();',
            'icon' => 'fas fa-floppy-disk',
            'label' => __('Save'),
            'success' => true,
        ),
        array(
            'url' => $this->Html->url(array('action' => 'view', $profile['id'],
                '?' => $query)),
            'icon' => 'fas fa-eye',
            'label' => __('Back to the profile'),
            'short' => __('View'),
        ),
        array(
            'url' => $this->Html->url(array('action' => 'simulate',
                $profile['id'], '?' => $query)),
            'onclick' => "event.preventDefault(); analystProfileCompare(this.getAttribute('href'));",
            'icon' => 'fas fa-flask',
            'label' => __('Open the full comparison'),
            'short' => __('Compare'),
        ),
        array(
            'url' => $this->Html->url(array('action' => 'export', $profile['id'])),
            'icon' => 'fas fa-file-export',
            'label' => __('Export JSON'),
            'short' => __('Export'),
        ),
    ),
    'maxTiles' => 4,
));
