<?php
    $modelForForm = 'Galaxy';

    echo $this->element('genericElements/Form/genericForm', [
        'form' => $this->Form,
        'data' => [
            'title' => $action == 'add' ? __('Add Galaxy') : __('Edit Galaxy'),
            'model' => $modelForForm,
            'fields' => array(
                array(
                    'field' => 'name',
                    'label' => __('Name'),
                    'class' => 'span4',
                    'type' => 'text',
                    'stayInLine' => true
                ),
                array(
                    'field' => 'namespace',
                    'label' => __('Namespace'),
                    'class' => 'span2',
                    'type' => 'text',
                ),
                array(
                    'field' => 'category',
                    'label' => __('Category'),
                    'class' => 'span3',
                    'type' => 'dropdown',
                    'options' => $galaxyCategories,
                    'empty' => __('Not classified'),
                    'description' => __('What this galaxy\'s clusters represent, so a consumer can ask for the galaxies naming a threat without knowing their names. Left unset means nobody has classified it.'),
                ),
                array(
                    'field' => 'sub_category',
                    'label' => __('Sub-category'),
                    'class' => 'span3',
                    'type' => 'dropdown',
                    'options' => array_filter($galaxySubCategories),
                    'empty' => __('No sub-category'),
                    // Without it CakePHP drops an option whose label matches
                    // an optgroup's - `technique` and `reference` are each a
                    // category and a sub-category, and would render nowhere.
                    'showParents' => true,
                    'description' => __('The finer distinction inside the category. Optional even when a category is set.'),
                ),
                array(
                    'field' => 'distribution',
                    'options' => $distributionLevels,
                    'default' => isset($galaxy['Galaxy']['distribution']) ? $galaxy['Galaxy']['distribution'] : $initialDistribution,
                    'stayInLine' => 1,
                    'type' => 'dropdown'
                ),
                array(
                    'field' => 'id',
                    'type' => 'hidden',
                ),
                array(
                    'field' => 'uuid',
                    'type' => 'hidden',
                ),
                array(
                    'field' => 'version',
                    'type' => 'hidden',
                ),
                array(
                    'field' => 'description',
                    'label' => __('Description'),
                    'type' => 'textarea',
                    'class' => 'input span6',
                    'div' => 'input clear'
                ),
                array(
                    'field' => 'icon',
                    'label' => __('Icon'),
                    'class' => 'span6',
                    'type' => 'text',
                ),
                array(
                    'field' => 'kill_chain_order',
                    'label' => __('Kill Chain - For the Galaxy Matrix'),
                    'class' => 'span6',
                    'type' => 'textarea'
                ),
                array(
                    'field' => 'enabled',
                    'label' => __('Enabled'),
                    'type' => 'checkbox',
                ),
            ),
        ]
    ]);
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => $this->action === 'add' ? 'galaxy_add' : 'galaxy_edit'));
?>
<script type="text/javascript">
(function () {
    var subCategories = <?php echo json_encode($galaxySubCategories, JSON_HEX_TAG | JSON_HEX_AMP); ?>;
    var definitions = <?php echo json_encode($galaxyCategoryDescriptions, JSON_HEX_TAG | JSON_HEX_AMP); ?>;
    $(function () {
        var $category = $('#GalaxyCategory');
        var $subCategory = $('#GalaxySubCategory');
        if ($category.length === 0 || $subCategory.length === 0) {
            return;
        }
        var noSubCategory = $subCategory.find('option[value=""]').first().text();
        var $anchor = $category.closest('.input');
        var $static = $anchor.next('small.form-field-description');
        var $definition = $('<small class="clear form-field-description"></small>')
            .insertAfter($static.length ? $static : $anchor);

        function refresh(reset) {
            var category = $category.val();
            var current = reset ? '' : $subCategory.val();
            var available = subCategories[category] || {};
            $subCategory.empty().append($('<option></option>').val('').text(noSubCategory));
            var offered = false;
            $.each(available, function (subCategory, label) {
                $subCategory.append($('<option></option>').val(subCategory).text(label));
                offered = offered || subCategory === current;
            });
            // A sub-category set from outside this form - over the API, or by a
            // definition file - stays on offer, so opening the form and
            // saving it does not quietly drop what is stored.
            if (current && !offered) {
                $subCategory.append($('<option></option>').val(current).text(current));
            }
            $subCategory.val(current);
            $definition.text(definitions[category] || '');
        }

        $category.on('change', function () { refresh(true); });
        refresh(false);
    });
})();
</script>
