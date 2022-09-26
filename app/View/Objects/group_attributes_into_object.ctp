<button class="btn btn-inverse" onclick="showObjectProposition()"><i class="fas fa-chevron-left"></i></button>
<?php
echo $this->Form->create('Object', array('url' => $baseurl . '/objects/groupAttributesIntoObject/' . $event_id . '/' . $selectedTemplateTd));
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
    'style' => 'display:none;margin-bottom:5px;',
    'value' => 0
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
            echo $this->Form->input('selectedTemplateId', array('type' => 'hidden', 'value' => $selectedTemplateTd));
            echo $this->Form->input('selectedAttributeIds', array('type' => 'hidden', 'value' => json_encode($selectedAttributeIds)));
            echo $this->Form->input('selectedObjectRelationMapping', array('value' => ''));
            echo $this->Form->end();
        ?>
    </div>
</dl>

<div style="border: 2px solid #3465a4 ; border-radius: 3px; overflow: hidden;">
    <table class="table table-striped table-condensed" style="margin-bottom: 0px;">
        <thead>
            <tr>
                <th><?php echo __('ID'); ?></th>
                <th><?php echo __('Name :: Type'); ?></th>
                <th><?php echo __('Date'); ?></th>
                <th><?php echo __('Category'); ?></th>
                <th><?php echo __('Value'); ?></th>
                <th><?php echo __('Distribution'); ?></th>
            </tr>
        </thead>
        <tbody id="attributeMappingBody">
            <?php foreach ($attributes as $attribute): ?>
                <tr>
                    <td class="attributeId"><?= intval($attribute['Attribute']['id']); ?></td>
                    <td>
                        <span style="display: block;">
                            <select class="attributeMapping" style="margin-bottom: 5px;">
                                <?php foreach ($object_relations[$attribute['Attribute']['type']] as $object_relation): ?>
                                    <option value="<?php echo h($object_relation['object_relation']); ?>" title="<?php echo h($object_relation['description']); ?>"><?php echo h($object_relation['object_relation']); ?></option>
                                <?php endforeach; ?>
                            </select>
                            :: <?php echo h($attribute['Attribute']['type']); ?>
                        </span>
                        <i class="objectRelationDescription apply_css_arrow"><?php echo h($object_relations[$attribute['Attribute']['type']][0]['description']); ?></i>
                    </td>
                    <td style="min-width: 75px;"><?= $this->Time->date($attribute['Attribute']['timestamp']); ?></td>
                    <td><?php echo h($attribute['Attribute']['category']); ?></td>
                    <td style="white-space: nowrap;"><?php echo h($attribute['Attribute']['value']); ?></td>
                    <td><?php echo h($distributionLevels[$attribute['Attribute']['distribution']]); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<?php if ($skipped_attributes > 0): ?>
    <div class="alert" style="margin-top: 15px;">
        <strong><?php echo __('Skipped'); ?></strong> <?php echo h($skipped_attributes) . __(' Attribute(s)') ?>
    </div>
<?php endif; ?>

<?php if (!empty($object_references)): ?>
    <div class="alert alert-danger" style="margin-top: 15px;">
        <strong><?php echo __('Dropped Object references'); ?></strong>
        <div><?php echo __('As these Attributes are converted into an Objects, the meaning of the Refences might change. If you whish to preserve the References, you will have to created them after the merge. Take note of them!') ?></div>
        <div><?php echo __('The following References will be dropped after the merge:') ?></div>
        <div style="max-height: 170px; overflow-y: auto; border: 1px solid #e6cace; border-radius: 4px; padding: 5px;">
            <table style="margin: 2px;">
            <?php foreach ($object_references as $object_reference): ?>
                <?php $object_reference = $object_reference['ObjectReference']; ?>
                    <tr>
                        <td><span style="margin-right: 5px;">&#8226;</span></td>
                        <td><?php echo sprintf('<strong>%s</strong> (%s)', h($object_reference['object_name']), h($object_reference['object_id'])); ?></td>
                        <td style="text-align: center;">
                            <div style="display: inline-block; position: relative; margin: 10px 10px 0px 10px; top: -8px;">
                                <span style=""><?php echo h($object_reference['relationship_type']); ?></span>
                                <i class="fas fa-long-arrow-alt-right" style="font-size: x-large; position: absolute; left: calc(50% - 10px); top: 10px;"></i>
                            </div>
                        </td>
                        <td><?php echo sprintf('<strong>%s</strong> (%s)', h($object_reference['attribute_name']), h($object_reference['referenced_id'])); ?></td>
                        <?php if ($object_reference['comment'] !== ''): ?>
                            <td><span style="margin: 0px 10px;">-</span></td>
                            <td style="margin-left: 10px"><?php echo h($object_reference['comment']); ?></td>
                        <?php endif; ?>
                    </tr>
            <?php endforeach; ?>
            </table>
        </div>
    </div>
<?php endif; ?>


<div style="margin-top: 15px; text-align: center;">
    <div>
        <button class="btn btn-primary" onclick="submitMergeAttributeIntoObjectForm(this);"><?php echo __('Merge above Attributes into an Object'); ?></button>
    </div>
    <span class="red bold" data-original-title="" title="">
        <?php echo __('Selected Attributes will be %s deleted', '<strong style="font-size: medium">' . ($hard_delete_attribute ? __('hard') : __('soft')) . '</strong>'); ?>
    </span>
</div>

<script>
$(".Object_distribution_select").change(function() {
    checkAndEnable($(this).parent().find('.Object_sharing_group_id_select'), $(this).val() == 4);
});

$(".attributeMapping").change(function() {
    var $select = $(this);
    var text = $select.find(":selected").attr('title');
    $select.parent().parent().find('.objectRelationDescription').text(text);
});

function submitMergeAttributeIntoObjectForm(btn) {
    var $btn = $(btn);
    var $form = $('#ObjectGroupAttributesIntoObjectForm');
    var attribute_mapping = {};
    $('#attributeMappingBody').find('tr').each(function() {
        var $tr = $(this);
        var attr_id = $tr.find('.attributeId').text();
        var attr_mapping = $tr.find('.attributeMapping').val();
        attribute_mapping[attr_id] = attr_mapping;
    });
    $('#ObjectSelectedObjectRelationMapping').val(JSON.stringify(attribute_mapping));
    var btn_text_backup = '';
    $.ajax({
        data: $form.serialize(),
        beforeSend: function () {
            btn_text_backup = $btn.text();
            $btn.html('<it class="fa fa-spinner fa-spin"></it>');
        },
        success: function (data) {
            if (data.errors !== undefined) {
                showMessage('fail', responseArray.errors);
                $btn.text(btn_text_backup);
                return false;
            } else {
                location.reload();
            }
        },
        error: function() {
            showMessage('fail', 'Could not merge Attributes into an Object.');
            showObjectProposition();
        },
        type: "post",
        url: $form.attr('action')
    });
}
</script>
