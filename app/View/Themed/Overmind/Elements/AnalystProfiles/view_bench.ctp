<?php
/**
 * The view's value under assessment, as a rail card. The page carries no
 * form, so analyst-profile.js answers its Try it by reloading with
 * `?value=`, and the section cards show each weight's contribution.
 *
 * @var array $profile
 * @var array $bench
 * @var array $bands
 */
?>
<section class="card ap-rcard" aria-label="<?= h(__('Try it on a value')) ?>">
    <header class="ap-rcard-h">
        <span class="ap-vcard-ico" aria-hidden="true"><i class="fas fa-flask"></i></span>
        <h2 class="ap-rcard-t"><?= h(__('Try it on a value')) ?></h2>
    </header>
    <div class="wb-bench">
        <?= $this->element('AnalystProfiles/bench', array(
            'bench' => $bench,
            'bands' => $bands,
            'full' => false,
            'profileId' => $profile['id'],
        )) ?>
    </div>
</section>
