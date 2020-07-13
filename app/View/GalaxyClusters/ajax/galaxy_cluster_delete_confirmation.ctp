<div class="confirmation">
    <legend><?php echo __('Galaxy Cluster Deletion');?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
    <h6><?php echo sprintf(__('Are you sure you want to delete Galaxy Cluster %s (%s)?'), sprintf('<i style="font-size: larger">%s</i>', h($cluster['value'])), h($cluster['id']));?></h6>
    <ul>
        <li><?php echo sprintf(__('%s a cluster propagates the deletion to other instances and lets you restore it in the future'), sprintf('<strong class="blue">%s</strong>', __('Soft-deleting')));?></li>
        <li><?php echo sprintf(__('%s a cluster permanentaly deletes it and prevents it be created again by blocklisting it'), sprintf('<strong class="red">%s</strong>', __('Hard-deleting')));?></li>
        <ul>
            <li><?php echo sprintf(__('For default clusters, you can restore the cluster at any time by force updating your galaxies'));?></li>
        </ul>
    </ul>
    <div style="display: flex">
        <?php
            echo $this->Form->postButton(
                '<i class="' . $this->FontAwesome->getClass('trash') . ' fa-trash"></i> ' . __('Soft-delete'),
                '/galaxy_clusters/delete/' . h($cluster['id']),
                array('class' => 'btn btn-primary')
            );
            echo '<span style="width: 0.5em";></span>';
            echo $this->Form->postButton(
                '<i class="' . $this->FontAwesome->getClass('ban') . ' fa-ban"></i> ' . __('Hard-delete'),
                sprintf('/galaxy_clusters/delete/%s/%s', h($cluster['id']), 1),
                array('class' => 'btn btn-danger')
            );
        ?>
        <button type="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" class="btn btn-inverse" style="margin-left: auto; height: fit-content;" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No');?></span>
    </div>
</div>
<?php
    echo $this->Form->end();
?>
</div>
