<div class="servers form">
    <div style="position:absolute;right:40px;width:300px;top:90px;">
		<label for="TemplateSelect">Templates</label>
		<?php
			$options = '<option value="">None</option>';
            foreach($allValidApisFormated as $scope => $actions) {
                $options .= sprintf('<optgroup label="%s">', $scope);
                foreach($actions as $action) {
			        $options .= sprintf('<option value="%s">%s</option>', $action['url'], $action['action']);
                }
            }
			echo sprintf('<select id="TemplateSelect">%s</select>', $options);
		?>
		<div id="apiInfo" style="margin-top: 15px;"></div>
	</div>

	<div style="position:absolute;left:770px;width:calc(100% - 1130px);top:100px;">
        <div class="selected-path-container">
		    <h3 id="selected-path" >---</h3>
        </div>
		<div id="querybuilder"></div>
        <button id="btn-inject" type="button" class="btn btn-success"><i class="fa fa-mail-forward" style="transform: scaleX(-1);"></i> Inject </button>
        <button id="btn-apply" type="button" class="btn btn-default"><i class="fa fa-list-alt"></i> Show rules </button>
	</div>
<?php echo $this->Form->create('Server');?>
    <fieldset>
        <legend><?php echo __('REST client');?></legend>
    <?php
        echo $this->Form->input('method', array(
            'label' => __('Relative path to query'),
            'options' => array(
                'GET' => 'GET',
                'POST' => 'POST'
            )
        ));
        ?>
            <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->input('url', array(
            'label' => __('Relative path to query'),
            'class' => 'input-xxlarge'
        ));
	?>
		<div class="input clear" style="width:100%;">
	<?php
		echo $this->Form->input('use_full_path', array(
			'label' => 'Use full path - disclose my apikey',
            'type' => 'checkbox'
        ));
    ?>
        <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->input('show_result', array(
            'type' => 'checkbox'
        ));
		echo $this->Form->input('skip_ssl_validation', array(
			'type' => 'checkbox',
			'label' => 'Skip SSL validation'
		));

    ?>
        <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->input('header', array(
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge',
                'default' => !empty($this->request->data['Server']['header']) ? $this->request->data['Server']['header'] : $header
        ));
    ?>
        <div class="input clear" style="width:100%;">
    <?php
        echo $this->Form->input('body', array(
                'type' => 'textarea',
                'div' => 'input clear',
                'class' => 'input-xxlarge'
        ));
    ?>
        <div class="input clear" style="width:100%;">
		<div id="template_description" style="display:none;width:700px;" class="alert alert-error">Fill out the JSON template above, make sure to replace all placeholder values. Fields with the value "optional" can be removed.</div>
    <?php
        echo $this->Form->submit('Run query', array('class' => 'btn btn-primary'));
        echo $this->Form->end();
    ?>
        <hr />
	</fieldset>
    <?php
		$formats = array('Raw', 'JSON', 'HTML');
		if (!empty($data['code']) && $data['code'] < 300) {
			$query_formats = array('curl' => 'cURL', 'python' => 'PyMISP');
			echo '<ul class="nav nav-tabs" style="margin-bottom:5px;">';
			foreach ($query_formats as $format => $formatName) {
				if (!empty(${$format})) {
					echo sprintf('<li><a href="#%s" data-toggle="tab">%s</a></li>', 'tab' . $format, $formatName);
				}
			}
			echo '</ul>';
			echo '<div class="tab-content">';
			foreach ($query_formats as $format => $formatName) {
				if (!empty(${$format})) {
					echo sprintf('<div class="tab-pane" id="%s"><pre>%s</pre></div>', 'tab' . $format, ${$format});
				}
			}
			echo '</div>';
		}
	?>
	<?php
        if (!empty($data['data'])):
            echo sprintf('<h3>%s</h3>', __('Response'));
            echo sprintf('<div><span class="bold">%s</span>: %d</div>', __('Response code'), h($data['code']));
            echo sprintf('<div><span class="bold">%s</span>: %s</div>', __('Request duration'), h($data['duration']));
            echo sprintf('<div class="bold">%s</div>', __('Headers'));
            foreach ($data['headers'] as $header => $value) {
				if (is_array($value)) {
					$value = implode(',', $value);
				}
            	echo sprintf('&nbsp;&nbsp;<span class="bold">%s</span>: %s<br />', h($header), h($value));
    		}
            $format_toggles = '';
            foreach ($formats as $k => $format) {
              $position = '';
              if ($k == 0) {
                $position = '-left';
              }
              if ($k == (count($formats) -1)) {
                $position = '-right';
              }
              $format_toggles .= sprintf('<span class="btn btn-inverse qet toggle%s format-toggle-button" data-toggle-type="%s">%s</span>', $position, $format, $format);
            }
            echo sprintf('<div style="padding-bottom:24px;">%s</div>', $format_toggles);
            echo sprintf('<div class="hidden" id="rest-response-hidden-container">%s</div>', h($data['data']));
            echo '<div id="rest-response-container"></div>';
        endif;
    ?>
</div>

<?php
    echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'rest'));
?>

<?php
    echo $this->Html->script('doT');
    echo $this->Html->script('extendext');
    echo $this->Html->script('moment-with-locales');
    echo $this->Html->css('query-builder.default');
    echo $this->Html->script('query-builder');
    echo $this->Html->css('chosen.min');
    echo $this->Html->script('chosen.jquery.min');
?>
<script type="text/javascript">
	// tooltips
	var thread = null;
	function setApiInfoBox(isTyping) {
		clearTimeout(thread);
        if (isTyping) {
            var delay = 200;
        } else {
            var delay = 0;
        }
		var $this = $(this);
		var payload = {
			"url": $('#ServerUrl').val()
		};
		if (payload) {
			thread = setTimeout(
				function() {
					$.ajax({
						type: "POST",
						url: '/servers/getApiInfo',
						data: payload,
						success:function (data, textStatus) {
							$('#apiInfo').html(data);
                            addHoverInfo($('#ServerUrl').data('urlWithoutParam'));
						}
					});
				},
                delay
			);
		} else {
			$('#apiInfo').empty();
		}
	}

    var allValidApis;
    var fieldsConstraint;
    var querybuilderTool;
	$(document).ready(function () {
		allValidApis = <?php echo json_encode($allValidApis); ?>;
        fieldsConstraint = <?php echo json_encode($allValidApisFieldsContraint); ?>;

		insertRawRestResponse();
		$('.format-toggle-button').bind('click', function() {
			$('#rest-response-container').empty();
			if ($(this).data('toggle-type') == 'Raw') {
				insertRawRestResponse();
			} else if ($(this).data('toggle-type') == 'HTML') {
				insertHTMLRestResponse();
			} else if ($(this).data('toggle-type') == 'JSON') {
				insertJSONRestResponse();
			}
		});
		$('#ServerUrl').keyup(function() {
            $('#TemplateSelect').val($(this).val()).trigger("chosen:updated").trigger("change");
		});
		$('#TemplateSelect').change(function() {
			var selected_template = $('#TemplateSelect').val();
			if (selected_template !== '' && allValidApis[selected_template] !== undefined) {
				$('#template_description').show();
				$('#ServerMethod').val('POST');
				$('#ServerUrl').val(allValidApis[selected_template].url);
				$('#ServerUrl').data('urlWithoutParam', selected_template);
				$('#ServerBody').val(allValidApis[selected_template].body);
				setApiInfoBox(false);
                updateQueryTool(selected_template);
			}
		});

        /* Query builder */

        // Fix for Bootstrap Datepicker
        $('#builder-widgets').on('afterUpdateRuleValue.queryBuilder', function(e, rule) {
            if (rule.filter.plugin === 'datepicker') {
                rule.$el.find('.rule-value-container input').datepicker('update');
            }
        });

        querybuilderTool = $('#querybuilder').queryBuilder({
            plugins: {
                'filter-description' : {
                    mode: 'inline'
                },
                'unique-filter': null,
                'bt-tooltip-errors': null,
                'chosen-selectpicker': null,
                'not-group': null
            },
            allow_empty: true,

            filters: [{
                id: 'noValidFilters',
                label: 'No valid filters, Pick an endpoint first',
                type: 'string'
            }],
            icons: {
              add_group: 'fa fa-plus-square',
              add_rule: 'fa fa-plus-circle',
              remove_group: 'fa fa-minus-square',
              remove_rule: 'fa fa-minus-circle',
              error: 'fa fa-exclamation-triangle'
            }
        });
        querybuilderTool = querybuilderTool[0].queryBuilder;
        
        $('#btn-apply').on('click', function() {
            var result = querybuilderTool.getRules();
            
            if (!$.isEmptyObject(result)) {
                alert(JSON.stringify(result, null, 2));
            }
        });
        $('#btn-inject').on('click', function() {
            injectQuerybuilterRulesToBody();
        });

        /* Apply jquery chosen where applicable */
        $("#TemplateSelect").chosen();
	});
</script>

<script>
    function updateQueryTool(url) {
        var apiJson = allValidApis[url];
        var filtersJson = fieldsConstraint[url];
        var filters = [];
        for (var k in filtersJson) {
            if (filtersJson.hasOwnProperty(k)) {
                var filter = filtersJson[k];
                var helptext = filter.help;
                if (helptext !== undefined) {
                    filter.description = helptext;
                }
                if (filter.input === 'select') {
                    filter.plugin = 'chosen';
                }
                filter.unique = filter.unique !== undefined ? filter.unique : true;
                filters.push(filter);
            }
        }
        if (filters.length > 0) {
            querybuilderTool.setFilters(true, filters);
        }

        // add and lock mandatory fields
        var mandatoryFields = apiJson.mandatory;
        if (mandatoryFields !== undefined && mandatoryFields.length > 0) {
            var rules = {
                "condition": "AND",
                "rules": [
                    {
                        "condition": "AND",
                        "rules": [],
                        "not": false,
                        "valid": true,
                        "flags": {
                            "condition_readonly": true,
                            "no_add_rule": true,
                            "no_add_group": true,
                            "no_delete": true
                        }
                    }
                ],
                "not": false,
                "valid": true
            };
            mandatoryFields.forEach(function(mandatory) {
                var r = filtersJson[mandatory];
                r.flags = {
                    no_delete: true,
                    filter_readonly: true
                };
                rules.rules[0].rules.push(r);
            })
        } else {
            var rules = {
                "condition": "AND",
                "rules": [],
                "not": false,
                "valid": true
            };
        }

        // add Params input field
        var paramFields = apiJson.params;
        $('#divAdditionalParamInput').remove();
        if (paramFields !== undefined && paramFields.length > 0) {
            var div = $('.selected-path-container');
            var additionalInput = $('<div class="query-builder">'
                    + '<div class="rules-list">'
                        + '<div id="divAdditionalParamInput" class="rule-container">'
                            + '<input id="paramInput" class="form-control" type="text" style="margin-bottom: 0px;" placeholder="' + paramFields[0] + '">'
                        + '</div>'
                    + '</div>'
                + '</div>');
            div.append(additionalInput);
        }

        querybuilderTool.setRules(rules, false);
    }

    function injectQuerybuilterRulesToBody() {
        var rules_root = querybuilderTool.getRules();
        var result = {};
        recursiveInject(result, rules_root, false);
        var jres = JSON.stringify(result, null, '    ');
        $('#ServerBody').val(jres);

        // inject param to url
        var param = $('#paramInput').val();
        if (param !== undefined) {
            var origVal = $('#ServerUrl').val();
            var newVal = origVal.replace(/(\[\w+\]){1}/, param);
            $('#ServerUrl').val(newVal);
        }
    }

    function recursiveInject(result, rules, isNot) {
        if (rules.rules === undefined) { // add to result
            var field = rules.field.split(".")[1];
            var value = rules.value;
            var operator_notequal = rules.operator === 'not_equal' ? true : false;
            var negate = isNot ^ operator_notequal;
            value = negate ? '!' + value : value;
            if (result.hasOwnProperty(field)) {
                if (Array.isArray(result[field])) {
                    result[field].push(value);
                } else {
                    result[field] = [result[field], value];
                }
            } else {
                result[field] = value;
            }
        }
        else if (Array.isArray(rules.rules)) {
            rules.rules.forEach(function(subrules) {
               recursiveInject(result, subrules, isNot ^ rules.not) ;
            });
        }
    }

    function addHoverInfo(url) {
        if (allValidApis[url] === undefined) {
            return;
        }

        var authorizedParamTypes = ['mandatory', 'optional'];

        var todisplay = allValidApis[url].controller + '/' + allValidApis[url].action + '/';
        $('#selected-path').text(todisplay);

        authorizedParamTypes.forEach(function(paramtype) {
            if (allValidApis[url][paramtype] !== undefined) {
                allValidApis[url][paramtype].forEach(function(field) {
                    if (fieldsConstraint[url][field] !== undefined) { // add icon
                        var apiInfo = fieldsConstraint[url][field].help;
                        if(apiInfo !== undefined && apiInfo !== '') {
                            $('#infofield-'+field).popover({
                                trigger: 'hover',
                                //placement: 'right',
                                content: apiInfo,
                            });
                        } else { // no help, delete icon
                            $('#infofield-'+field).remove();
                        }
                    }
                });
            }
        });
    }
</script>

