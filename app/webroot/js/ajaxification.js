function deleteObject(type, id, event) {
	if (confirm("Are you sure you want to delete Attribute #" + id + "?")) {
		var name = '#Attribute' + '_' + id + '_delete';
		var formData = $(name).serialize();
		$.ajax({
			data: formData, 
			success:function (data, textStatus) {
				updateAttributeIndexOnSuccess(event);
			}, 
			type:"post", 
			url:"/" + type + "/delete/" + id,
		});
	}	
}

function updateAttributeIndexOnSuccess(event) {
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		dataType:"html", 
		success:function (data, textStatus) {
			$(".loading").hide();
			$("#attributes_div").html(data);
		}, 
		url:"/events/view/" + event + "/attributesPage:1",
	});
}

// if someone clicks an inactive field, replace it with the hidden form field. Also, focus it and bind a focusout event, so that it gets saved if the user clicks away.
// If a user presses enter, submit the form
function activateField(type, id, field, event) {
	resetForms();
	var name = '#' + type + '_' + id + '_' + field;
	$(name + '_form').show();
	$(name + '_field').focus();
	inputFieldButtonActive(name + '_field');
	if (field == 'value' || field == 'comment') {
		$(name + '_field').on('keyup mouseover', function () {
		    autoresize(this);
		});
	}
	$(name + '_form').submit(function(e){ 
		e.preventDefault();
		submitForm(type, id, field, event);
		return false;
	});
	
	$(name + '_form').bind("focusout", function() {
		inputFieldButtonPassive(name + '_field');
	});

	$(name + '_form').bind("focusin", function(){
		inputFieldButtonActive(name + '_field');
	});
	
	$(name + '_form').bind("keydown", function(e) {
		if (e.ctrlKey && (e.keyCode == 13 || e.keyCode == 10)) {
			submitForm(type, id, field, event);
		}
	});
	
	$(name + '_field').closest('.inline-input-container').children('.inline-input-accept').bind('click', function() {
		submitForm(type, id, field, event);
	});
	
	$(name + '_field').closest('.inline-input-container').children('.inline-input-decline').bind('click', function() {
		resetForms();
	});

	$(name + '_solid').hide();
}

function resetForms() {
	$('.inline-field-solid').show();
	$('.inline-field-form').hide();
}

function inputFieldButtonActive(selector) {
	$(selector).closest('.inline-input-container').children('.inline-input-accept').removeClass('inline-input-passive').addClass('inline-input-active');
	$(selector).closest('.inline-input-container').children('.inline-input-decline').removeClass('inline-input-passive').addClass('inline-input-active');
}

function inputFieldButtonPassive(selector) {
	$(selector).closest('.inline-input-container').children('.inline-input-accept').addClass('inline-input-passive').removeClass('inline-input-active');
	$(selector).closest('.inline-input-container').children('.inline-input-decline').addClass('inline-input-passive').removeClass('inline-input-active');
}

function autoresize(textarea) {
    textarea.style.height = '20px';
    textarea.style.height = (textarea.scrollHeight) + 'px';
}

// submit the form - this can be triggered by unfocusing the activated form field or by submitting the form (hitting enter)
// after the form is submitted, intercept the response and act on it 
function submitForm(type, id, field, event) {
	var name = '#' + type + '_' + id + '_' + field;
	$.ajax({
		data: $(name + '_field').closest("form").serialize(), 
		success:function (data, textStatus) {
			handleAjaxEditResponse(data, event);
		}, 
		error:function() {
			alert('Request failed. This may be caused by the CSRF protection blocking your request. The forms will now be refreshed to resolve the issue.');
			updateAttributeIndexOnSuccess(event);
		},
		type:"post", 
		url:"/attributes/editField/" + id
	});
	$(name + '_field').unbind("keyup");
	$(name + '_form').unbind("focusout");
	return false;
};

function handleAjaxEditResponse(data, event) {
	if (data == "\"saved\"") updateAttributeIndexOnSuccess(event);
	else {
		updateAttributeIndexOnSuccess(event);
	}
}

function handleAjaxMassDeleteResponse(data, event) {
	if (data == "\"saved\"") updateAttributeIndexOnSuccess(event);
	else {
		updateAttributeIndexOnSuccess(event);
	}
}

$(function(){
    $('a:contains("Delete")').removeAttr('onclick');
    $('a:contains("Delete")').click(function(e){
        e.preventDefault();
        var form = $(this).prev();
        url = $(form).attr("action");
        $.post(url);
        return false;
    });
});

function toggleAllAttributeCheckboxes() {
	if ($(".select_all").is(":checked")) {
		$(".select_attribute").prop("checked", true);
	} else {
		$(".select_attribute").prop("checked", false);
	}
}

function attributeListAnyCheckBoxesChecked() {
	if ($('input[type="checkbox"]:checked').length > 0) $('.mass-select').show();
	else $('.mass-select').hide();
}


function deleteSelectedAttributes(event) {
	var answer = confirm("Are you sure you want to delete all selected attributes?");
	if (answer) {
		var selected = [];
		$(".select_attribute").each(function() {
			if ($(this).is(":checked")) {
				var test = $(this).data("id");
				selected.push(test);
			}
		});
		$('#AttributeIds').attr('value', JSON.stringify(selected));
		var formData = $('#delete_selected').serialize();
		$.ajax({
			data: formData, 
			type:"POST", 
			url:"/attributes/deleteSelected/",
			success:function (data, textStatus) {
				handleAjaxMassDeleteResponse(data, event);
			}, 
		});
	}
	return false;
}