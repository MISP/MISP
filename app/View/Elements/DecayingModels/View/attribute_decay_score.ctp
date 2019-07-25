<div>
    <?php if (isset($object['decay_score'])): ?>
        <?php foreach ($object['decay_score'] as $dc): ?>
            <?php $class_score = $dc['decayed'] ? 'alert-error' : 'alert-success'; ?>
            <div style="display: block; margin-bottom: 3px;" class="input-prepend input-append">
                <span class="add-on ellipsis-overflow" style="max-width: 12em;" title="<?php echo h($dc['DecayingModel']['name']); ?>"><?php echo h($dc['DecayingModel']['name']); ?></span>
                <span id="simulation-current-score" class="add-on <?php echo $class_score ?>"><?php echo round($dc['score'], 2) ?></span>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>
</div>
