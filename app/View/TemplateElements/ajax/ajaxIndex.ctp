<div id="ajaxTemplateElementsIndex">
	<h2>Template Elements</h2>
	<ul <?php if ($mayModify): ?> id="sortable" <?php endif; ?> style="list-style:none; margin:0px;">
				<?php
				foreach ($elements as $k => $element):
					echo $this->element('templateElements/templateRow' . ucfirst($element['TemplateElement']['element_definition']), array('element' => $element, 'element_id' => $element['TemplateElement']['id']));
				endforeach;
			?>
	</ul>
	<?php if ($mayModify): ?>
	<div id="AddTemplateElementDiv" role="button" tabindex="0" aria-label="Add a new template element" title="Add a new template element" class="addTemplateElement useCursorPointer" onClick="templateAddElementClicked(<?php echo $id; ?>);">+</div>
	<?php endif; ?>
</div>
<script type="text/javascript">
$(function() {
	//Return a helper with preserved width of cells
	var fixHelper = function(e, ui) {
		ui.children().each(function() {
			$(this).width($(this).width());
		});
		return ui;
	};

	$("#sortable").sortable({
		helper: fixHelper,
		update: function () {
			var order = [];

			$("#sortable").children().each(function (i) {
				var li = $(this);
				order[i] = li.attr("id");
			});

			saveElementSorting(JSON.stringify(order));
		}
	}).disableSelection();
});
</script>
