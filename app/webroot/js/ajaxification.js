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

function updateAttributeFieldOnSuccess(name, type, id, field, event) {
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			if (field != 'timestamp') {
				$(".loading").show();
			}
		}, 
		dataType:"html", 
		success:function (data, textStatus) {
			if (field != 'timestamp') {
				$(".loading").hide();
				$(name + '_solid').html(data);
				$(name + '_placeholder').empty();
				$(name + '_solid').show();
			} else {
				$('#' + type + '_' + id + '_' + 'timestamp_solid').html(data);
			}
		}, 
		url:"/attributes/fetchViewValue/" + id + "/" + field,
	});
}

function activateField(type, id, field, event) {
	var name = '#' + type + '_' + id + '_' + field;
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		dataType:"html", 
		success:function (data, textStatus) {
			$(".loading").hide();
			$(name + '_placeholder').html(data);
			postActivationScripts(name, type, id, field, event);
		}, 
		url:"/attributes/fetchEditForm/" + id + "/" + field,
	});
}

function postActivationScripts(name, type, id, field, event) {
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


// if someone clicks an inactive field, replace it with the hidden form field. Also, focus it and bind a focusout event, so that it gets saved if the user clicks away.
// If a user presses enter, submit the form
function activateField2(type, id, field, event) {
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
	$('.inline-field-placeholder').empty();
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
			handleAjaxEditResponse(data, name, type, id, field, event);
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

function handleAjaxEditResponse(data, name, type, id, field, event) {
	if (data == "\"saved\"") {
		updateAttributeFieldOnSuccess(name, type, id, field, event);
		updateAttributeFieldOnSuccess(name, type, id, 'timestamp', event);
	} else {
		updateAttributeFieldOnSuccess(name, type, id, field, event);
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