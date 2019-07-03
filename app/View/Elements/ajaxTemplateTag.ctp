<td>
    <div id="tag_bubble_<?php echo h($tag['Tag']['id']); ?>">
        <table>
            <tr>
                <td style="padding-right:0px;">
                    <span class="<?php echo ($editable == 'yes' ? 'tagFirstHalf' : 'tagComplete'); ?>" style="background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>"><?php echo h($tag['Tag']['name']); ?></span>
                </td>
                <?php if ($editable == 'yes'): ?>
                <td style="padding-left:0px;padding-right:5px;">
                    <span class="tagSecondHalf useCursorPointer" title="<?php echo __('Remove tag');?>" role="button" tabindex="0" aria-label="<?php echo __('Remove tag');?>" onClick="removeTemplateTag('<?php echo h($tag['Tag']['id']); ?>', '<?php echo h($tag['Tag']['name']); ?>');">x</span>
                </td>
                <?php endif; ?>
            </tr>
        </table>
    </div>
</td>
