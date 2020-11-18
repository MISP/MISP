<div class="confirmation">
    <?php
    echo $this->Form->create('GalaxyCluster', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/galaxy_clusters/' . $type . '/' . $cluster['GalaxyCluster']['id']));
    $extraTitle = "";
    if ($type == 'publish') {
        $message = __('Publish cluster %s', h($cluster['GalaxyCluster']['id']));
    } else {
        $message = __('Unpublish cluster %s', h($cluster['GalaxyCluster']['id']));
    }
    ?>

    <legend><?php echo $message;?></legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
        <?php
            if ($type == 'publish') {
                echo '<p>' . __('Are you sure you wish to publish the cluster?') . '</p>';
            } else {
                echo '<p>' . __('Are you sure you wish to unpublish the cluster?') . '</p>';
            }
        ?>
        <p class="bold"><?= sprintf('%s :: %s', h($cluster['GalaxyCluster']['type']), h($cluster['GalaxyCluster']['value'])) ?></p>
        <table>
            <tr>
                <td style="vertical-align:top">
                    <span role="button" tabindex="0" aria-label="<?php echo __('Publish');?>" title="<?php echo __('Publish');?>" id="PromptYesButton" class="btn btn-primary" onClick="submitPublish()"><?php echo __('Yes');?></span>
                </td>
                <td style="width:540px;">
                </td>
                <td style="vertical-align:top;">
                    <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No');?></span>
                </td>
            </tr>
        </table>
    </div>
    <?php
        echo $this->Form->end();
    ?>
</div>
