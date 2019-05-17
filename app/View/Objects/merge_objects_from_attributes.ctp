<button class="btn btn-inverse" onclick="showObjectProposition()"><i class="fas fa-chevron-left"></i></button>
<?php
echo $this->Form->create('Object');
?>
<dl style="margin-top: 10px;">
    <dt><?php echo __('Object Template');?></dt>
    <dd><a href="<?php echo $baseurl . '/ObjectTemplates/view/' . h($template['ObjectTemplate']['id']) ?>"><?php echo Inflector::humanize(h($template['ObjectTemplate']['name'])) . ' v' . h($template['ObjectTemplate']['version']); ?></a></dd>
    <dt><?php echo __('Description');?></dt>
    <dd><?php echo h($template['ObjectTemplate']['description']); ?></dd>
    <dt><?php echo __('Meta category');?></dt>
    <dd><?php echo h($template['ObjectTemplate']['meta-category']); ?></dd>
    <dt><?php echo __('Distribution');?></dt>
    <dd>
    <?php echo $this->Form->input('Object.distribution', array(
      'class' => 'Object_distribution_select',
      'options' => $distributionData['levels'],
      'default' => $distributionData['initial'],
      'label' => false,
      'style' => 'margin-bottom:5px;',
      'div' => false
    )); ?>
    <?php echo $this->Form->input('Object.sharing_group_id', array(
    'class' => 'Object_sharing_group_id_select',
    'options' => $distributionData['sgs'],
    'label' => false,
    'div' => false,
    'style' => 'display:none;margin-bottom:5px;'
    )); ?>
    <dt><?php echo __('Comment');?></dt>
    <dd>
    <?php echo $this->Form->input('Object.comment', array(
      'type' => 'textarea',
      'style' => 'height:20px;width:400px;',
      'required' => false,
      'allowEmpty' => true,
      'label' => false,
      'div' => false
    )); ?>
    <div class="hidden">
        <?php
            echo $this->Form->input('selectedTemplateId', array('hiddenField' => false, 'value' => $selectedTemplateTd));
            echo $this->Form->input('selectedAttributeIds', array('hiddenField' => false, 'value' => $selectedAttributeIds));
            echo $this->Form->end();
        ?>
    </div>
</dl>

<div style="border: 2px solid #3465a4 ; border-radius: 3px; overflow: hidden;">
    <table class="table table-striped table-condensed" style="margin-bottom: 0px;">
        <thead>
            <tr>
                <th><?php echo __('ID'); ?></th>
                <th><?php echo __('Type'); ?></th>
                <th><?php echo __('Date'); ?></th>
                <th><?php echo __('Category'); ?></th>
                <th><?php echo __('Value'); ?></th>
                <th><?php echo __('Distribution'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($attributes as $attribute): ?>
                <tr>
                    <td><?php echo h($attribute['Attribute']['id']); ?></td>
                    <td>
                        <select>
                            <?php foreach ($object_relations[$attribute['Attribute']['type']] as $object_relation): ?>
                                <option value="<?php echo h($object_relation); ?>"><?php echo h($object_relation); ?></option>
                            <?php endforeach; ?>
                        </select>
                        :: <?php echo h($attribute['Attribute']['type']); ?>
                    </td>
                    <td><?php echo h(date('Y-m-d', $attribute['Attribute']['timestamp'])); ?></td>
                    <td><?php echo h($attribute['Attribute']['category']); ?></td>
                    <td><?php echo h($attribute['Attribute']['value']); ?></td>
                    <td><?php echo h($distributionLevels[$attribute['Attribute']['distribution']]); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<div style="margin-top: 15px; text-align: center;">
    <button class="btn btn-primary">Merge Selected Attribute into an Object</button>
</div>

<script>
$(".Object_distribution_select").change(function() {
    checkAndEnable($(this).parent().find('.Object_sharing_group_id_select'), $(this).val() == 4);
});
</script>
