<div data-tag-count="<?= count($eventTags) ?>">

<?php if (empty($eventTags)): ?>

    <div class="d-flex flex-column align-items-center justify-content-center
                text-muted py-4" data-tag-empty>
        <span class="misp-icon misp-icon-tag misp-hexagone mb-2 opacity-50" style="font-size:2em;"></span>
        <p class="mb-0 small fw-semibold">
            <?= __('No tags associated with this event.') ?>
        </p>
    </div>

<?php else: ?>

    <div class="d-flex flex-wrap gap-2 p-3" data-tag-list>
        <?php foreach ($eventTags as $et):
            $tag   = $et['Tag'];
            $local = !empty($et['local']);
        ?>
            <div data-tag-item
                 data-tag-name="<?= h(strtolower($tag['name'])) ?>">
                <?= $this->element('genericElementsBS5/Badges/tag', [
                    'tag'           => $tag,
                    'local'         => $local,
                    'hiddenClass'   => '',
                    'showFavourite' => false,
                ]); ?>
            </div>
        <?php endforeach; ?>
    </div>

    <div class="d-none text-center text-muted py-3 small"
         data-tag-noresult>
        <i class="fas fa-search me-1 opacity-50"></i>
        <?= __('No tags match your search.') ?>
    </div>

<?php endif; ?>

</div>
