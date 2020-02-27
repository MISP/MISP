<div class="hidden">
    <?php echo $this->Form->create('decayingToolRestSearch', array('url' => array('controller' => 'decayingModel', 'action' => 'decayingToolRestSearch', 'results')));?>
    <legend><?php echo __('Decaying Model RestSearch');?></legend>
    <fieldset>
        <?php echo $this->Form->input('filters'); ?>
    </fieldset>
    <?php echo $this->Form->end(); ?>
</div>
