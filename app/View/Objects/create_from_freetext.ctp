<div class="index">
    <h2><?php echo __('Create object');?></h2>
    <?= $this->Form->create('Object', array('url' => $baseurl . '/objects/createFromFreetext/' . $event['Event']['id'])); ?>
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
                echo $this->Form->input('selectedTemplateId', array('type' => 'hidden', 'value' => $template['ObjectTemplate']['id']));
                echo $this->Form->input('attributes', array('type' => 'hidden', 'value' => json_encode($attributes)));
                echo $this->Form->input('selectedObjectRelationMapping', ['value' => '', 'label' => false]);
                echo $this->Form->end();
                ?>
            </div>
    </dl>

    <div style="border: 2px solid #3465a4; border-radius: 3px; overflow: hidden;">
        <table class="table table-striped table-condensed" style="margin-bottom: 0px;">
            <thead>
            <tr>
                <th><?php echo __('Name :: Type'); ?></th>
                <th><?php echo __('Category'); ?></th>
                <th><?php echo __('Value'); ?></th>
                <th><?php echo __('To IDS'); ?></th>
                <th><?php echo __('Disable Correlation'); ?></th>
                <th><?php echo __('Comment'); ?></th>
                <th><?php echo __('Distribution'); ?></th>
            </tr>
            </thead>
            <tbody id="attributeMappingBody">
            <?php foreach ($attributes as $attribute): ?>
                <tr>
                    <td>
                        <span style="display: block;">
                            <select class="attributeMapping" style="margin-bottom: 5px;"<?= count($objectRelations[$attribute['type']]) === 1 ? ' disabled' : '' ?>>
                                <?php foreach ($objectRelations[$attribute['type']] as $object_relation): ?>
                                    <option title="<?= h($object_relation['description']); ?>"><?= h($object_relation['object_relation']); ?></option>
                                <?php endforeach; ?>
                            </select>
                            :: <?= h($attribute['type']); ?>
                        </span>
                        <i class="objectRelationDescription apply_css_arrow"><?= h($objectRelations[$attribute['type']][0]['description']); ?></i>
                    </td>
                    <td><?= h($attribute['category']); ?></td>
                    <td style="white-space: nowrap;"><?= h($attribute['value']); ?></td>
                    <td><?= $attribute['to_ids'] ? __('Yes') : __('No') ?></td>
                    <td><?= $attribute['disable_correlation'] ? __('Yes') : __('No') ?></td>
                    <td><?= h($attribute['comment']) ?></td>
                    <td><?= h($distributionLevels[$attribute['distribution']]); ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <div style="margin-top: 15px">
        <button class="btn btn-primary" onclick="submitCreateFromFreetext();"><?= __('Create Object'); ?></button>
    </div>

    <?php if (!empty($similar_objects)): ?>
        <h3 style="margin-top: 20px;"><?= __('This event already contains similar objects') ?></h3>
        <div class="row" style="margin-bottom: 20px;">
            <?php foreach ($similar_objects as $object): ?>
                <?php
                echo $this->element('Objects/object_similarities', array(
                    'object' => $object,
                    'attributes' => $attributes,
                    'template' => $template,
                    'simple_flattened_attribute_noval' => $simple_flattened_attribute_noval,
                    'simple_flattened_attribute' => $simple_flattened_attribute,
                   // 'merge_button_functionname' => 'setMergeObject'
                ));
                ?>
            <?php endforeach; ?>
            <?php if ($similar_objects_count > $similar_objects_display_threshold): ?>
                <div class="span5" style="margin-top: 20px;display: inline-block;float: unset;">
                    <div class="alert alert-info">
                        <h4><?php echo __('All similar objects not displayed...'); ?></h4>
                        <?php echo __('%s Similar objects found. %s not displayed', $similar_objects_count, $similar_objects_count-$similar_objects_display_threshold); ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>
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

    function submitCreateFromFreetext() {
        var $form = $('#ObjectCreateFromFreetextForm');
        var attribute_mapping = [];
        $('#attributeMappingBody').find('tr').each(function() {
            attribute_mapping.push($(this).find('.attributeMapping').val());
        });
        $('#ObjectSelectedObjectRelationMapping').val(JSON.stringify(attribute_mapping));

        xhr({
            type: "post",
            data: $form.serialize(),
            url: $form.attr('action'),
            success: function(data) {
                if (data.saved) {
                    window.location = baseurl + '/events/view/' + <?= $event['Event']['id'] ?>;
                } else {
                    showMessage('fail', data.errors);
                }
            }
        })
    }
</script>

<?= $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'event', 'menuItem' => 'freetextResults']);