<div style="width:100%;display:inline-block;">
    <?php
        foreach ($tags as $tag): ?>
            <div style="overflow:hidden;white-space:nowrap;float:left;">
                <div style="padding-right:0px;float: left;">
                    <?php if ($isSiteAdmin): ?>
                        <a href="<?php echo $baseurl;?>/events/index/searchtag:<?php echo h($tag['Tag']['id']); ?>" class="tagFirstHalf" style="background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
                    <?php else: ?>
                        <a href="<?php echo $baseurl;?>/events/index/searchtag:<?php echo h($tag['Tag']['id']); ?>" class=tag style="background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></a>
                    <?php endif; ?>
                </div>
                <div style="padding-left:0px;padding-right:5px;float:left;">
                    <?php if ($isSiteAdmin): ?>
                        <?php
                            echo $this->Form->create('Server', array('id' => 'removeTag_' . h($tag['Tag']['id']),  'url' => '/servers/removeTag/' . h($server['Server']['id']) . '/' . h($tag['Tag']['id']), 'style' => 'margin:0px;'));
                        ?>
                        <div title="<?php echo __('Remove tag');?>" role="button" tabindex="0" aria-label="<?php echo __('Remove tag');?>" class="tagSecondHalf useCursorPointer noPrint" onClick="removeServerTag('<?php echo h($server['Server']['id']); ?>', '<?php echo h($tag['Tag']['id']); ?>');">x</div>
                        <?php
                            echo $this->Form->end();
                        ?>
                    <?php else: ?>
                        &nbsp;
                    <?php endif; ?>
                </div>
            </div>
            <?php
        endforeach;
    ?>
        <div style="float:left">
            <?php if ($isSiteAdmin): ?>
                <button title="Add a tag" id="addTagButton" class="btn btn-inverse noPrint" style="line-height:10px; padding: 4px 4px;" onClick="getPopup('<?php echo h($server['Server']['id']); ?>', 'tags', 'selectTaxonomy');">+</button>
            <?php else:?>
                &nbsp;
            <?php endif; ?>
        </div>
</div>
