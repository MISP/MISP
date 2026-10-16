<td>
    <div id="tag_bubble_<?php echo h($tag['Tag']['id']); ?>">
        <span class="hinge-tags">
            <?= $this->TagChip->chip($tag, ['searchUrl' => '']) ?>
            <?php if ($editable == 'yes'): ?>
            <button type="button" class="hg-act noPrint" title="<?php echo __('Remove tag');?>" aria-label="<?php echo __('Remove tag');?>" onClick="removeTemplateTag('<?php echo h($tag['Tag']['id']); ?>');">&times;</button>
            <?php endif; ?>
        </span>
    </div>
</td>
