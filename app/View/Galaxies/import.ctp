<div class="form">
<?php echo $this->Form->create('Galaxy', array('enctype' => 'multipart/form-data'));?>
    <fieldset>
        <?php if (is_numeric($galaxyId)): ?>
            <legend><?php echo sprintf(
                __('Import galaxy clusters into %s galaxy'),
                sprintf('<strong>%s</strong>',  h($galaxy['Galaxy']['name']))
                ); ?></legend>
        <?php else: ?>
            <legend><?php echo __('Import galaxy clusters into a galaxy'); ?></legend>
        <?php endif; ?>
        <p><?php echo __('Paste a JSON of cluster to import or provide a JSON file below to add them into the selected Galaxy.'); ?></p>
    <div>
    <?php
        echo $this->Form->input('galaxy_id', array(
                'div' => 'input clear',
                'label' => __('Galaxy'),
                'options' => is_numeric($galaxyId) ? null : $galaxies,
                'class' => 'form-control span6',
                'value' => is_numeric($galaxyId) ? $galaxyId : '',
                'type' => is_numeric($galaxyId) ? 'hidden' : 'select'
        ));
        echo $this->Form->input('update_existing', array(
                'div' => 'input checkbox clear',
                'label' => __('Update existing galaxy cluster(s)'),
                'type' => 'checkbox',
                'class' => 'form-control',
        ));
        echo $this->Form->input('json', array(
                'div' => 'input clear',
                'label' => __('JSON'),
                'placeholder' => __('Galaxy JSON'),
                'class' => 'form-control span6',
                'type' => 'textarea',
                'rows' => 18
        ));
        echo $this->Form->input('submittedjson', array(
            'div' => 'input clear',
            'label' => __('JSON file'),
            'type' => 'file'
        ));
    ?>
    </div>
    </fieldset>
    <?php
        echo $this->Form->button(__('Import'), array('class' => 'btn btn-primary'));
        echo $this->Form->end();
    ?>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'import'));
