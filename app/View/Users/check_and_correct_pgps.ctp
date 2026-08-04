<div class="composites index">
    <h2><?php echo __('Failed GnuPGs?');?></h2><?php
if (0 == count($fails)):?>
    <p><?php echo __('No failed composites');?></p>
    <?php else:?>
    <ul>
    <?php foreach ($fails as $key => $value) echo '<li>' . $key . ' : ' . h($value) . '</li>'; ?>
    </ul>
    <?php
endif;?>
</div>
