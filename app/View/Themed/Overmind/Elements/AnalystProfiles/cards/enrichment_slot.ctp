<?php
/**
 * Where the enrichment card lands once it has asked misp-modules.
 *
 * @var bool $site_admin
 */
?>
<section class="ap-card ap-card-enrich" aria-busy="true"
         data-ap-card-src="<?= h($this->Html->url(array(
             'controller' => 'analyst_profiles', 'action' => 'enrichment'))) ?>">
    <?= $this->element('AnalystProfiles/cards/head', array(
        'icon' => 'puzzle-piece',
        'title' => $site_admin
            ? __('What the profiles ask for')
            : __('Your enrichment'),
    )) ?>
    <div class="ap-card-wait">
        <?= $this->element('genericElementsBS5/loader', array(
            'size' => 'sm',
            'label' => __('Asking the modules service'),
        )) ?>
    </div>
</section>
