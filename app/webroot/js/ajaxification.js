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
			cache: false,
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
		cache: false,
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
		cache: false,
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
		cache: false,
		success:function (data, textStatus) {
			$(".loading").hide();
			$(name + '_placeholder').html(data);
			postActivationScripts(name, type, id, field, event);
		}, 
		url:"/attributes/fetchEditForm/" + id + "/" + field,
	});
}

//if someone clicks an inactive field, replace it with the hidden form field. Also, focus it and bind a focusout event, so that it gets saved if the user clicks away.
//If a user presses enter, submit the form
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
		cache: false,
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

function submitTagForm(id) {
	$.ajax({
		data: $('#EventTag').closest("form").serialize(), 
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		success:function (data, textStatus) {
			loadEventTags(id);
		}, 
		error:function() {
			alert('Could not add tag.');
			loadEventTags(id);
		},
		complete:function() {
			$(".loading").hide();
		},
		type:"post", 
		url:"/events/addTag/" + id
	});
	return false;
}

function handleAjaxEditResponse(data, name, type, id, field, event) {
	responseArray = JSON.parse(data);
	if (responseArray.saved) {
		updateAttributeFieldOnSuccess(name, type, id, field, event);
		updateAttributeFieldOnSuccess(name, type, id, 'timestamp', event);
	} else {
		alert(responseArray.errors[field]);
		updateAttributeFieldOnSuccess(name, type, id, field, event);
	}
}

function handleAjaxMassDeleteResponse(data, event) {
	responseArray = JSON.parse(data);
	if (responseArray.saved) {
		updateAttributeIndexOnSuccess(event);
	} else {
		updateAttributeIndexOnSuccess(event);
	}
}

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
			cache: false,
			type:"POST", 
			url:"/attributes/deleteSelected/" + event,
			success:function (data, textStatus) {
				handleAjaxMassDeleteResponse(data, event);
			}, 
		});
	}
	return false;
}

function editSelectedAttributes(event) {
	$.get("/attributes/editSelected/"+event, function(data) {
		$("#attribute_add_form").show();
		$("#gray_out").show();
		$("#attribute_add_form").html(data);
	});
}

function getSelected() {
	var selected = [];
	$(".select_attribute").each(function() {
		if ($(this).is(":checked")) {
			var test = $(this).data("id");
			selected.push(test);
		}
	});
	return JSON.stringify(selected);
}

function editSelectedAttributes2(event) {
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
		cache: false,
		type:"POST", 
		url:"/attributes/editSelected/"+event,
		success:function (data, textStatus) {
			$("#attribute_add_form").show();
			$("#gray_out").show();
			$("#attribute_add_form").html(data);
			//handleAjaxMassDeleteResponse(data, event);
		}, 
	});
}

function loadEventTags(id) {
	$.ajax({
		dataType:"html", 
		cache: false,
		success:function (data, textStatus) {
			$(".eventTagContainer").html(data);
		}, 
		url:"/tags/showEventTag/" + id,
	});
}

function removeEventTag(event, tag) {
	var answer = confirm("Are you sure you want to remove this tag from the event?");
	if (answer) {
		var formData = $('#removeTag_' + tag).serialize();
		$.ajax({
			beforeSend: function (XMLHttpRequest) {
				$(".loading").show();
			}, 
			data: formData, 
			type:"POST", 
			cache: false,
			url:"/events/removeTag/" + event + '/' + tag,
			success:function (data, textStatus) {
				loadEventTags(event);
				//handleAjaxMassDeleteResponse(data, event);
			}, 
			complete:function() {
				$(".loading").hide();
			}
		});
	}
	return false;
}

function clickCreateButton(event) {
	$.get( "/attributes/add/" + event, function(data) {
		$("#attribute_add_form").show();
		$("#gray_out").show();
		$("#attribute_add_form").html(data);
	});
}

function submitPopoverForm(event, referer) {
	var url = null;
	if (referer == 'add') url = "/attributes/add/" + event;
	if (referer == 'massEdit') url = "/attributes/editSelected/" + event;
	if (url !== null) {
		$.ajax({
			beforeSend: function (XMLHttpRequest) {
				$(".loading").show();
				$("#gray_out").hide();
				$("#attribute_add_form").hide();
			}, 
			data: $("#submitButton").closest("form").serialize(), 
			success:function (data, textStatus) {
				handleAjaxPopoverResponse(data, event, url);
				$(".loading").show();
			}, 
			type:"post", 
			url:url
		});
	}
};

function handleAjaxPopoverResponse(response, event, url) {
	responseArray = JSON.parse(response);
	if (responseArray.saved) {	
		updateAttributeIndexOnSuccess(event);
	} else {
		var savedArray = saveValuesForPersistance();
		$.ajax({
			async:true, 
			dataType:"html", 
			success:function (data, textStatus) {
				$("#gray_out").show();
				$("#attribute_add_form").show();
				$("#attribute_add_form").html(data);
				handleValidationErrors(responseArray.errors);
				if (!isEmpty(responseArray)) {
					$("#formWarning").show();
					$("#formWarning").html('The attribute(s) could not be saved. Please, try again.');
				}
				recoverValuesFromPersistance(savedArray);
				$(".loading").hide();
			},
			url:url
		});	
	}
}

function isEmpty(obj) {
	var name;
	for (name in obj) {
		return false;
	}
	return true;
}

//before we update the form (in case the action failed), we want to retrieve the data from every field, so that we can set the fields in the new form that we fetch 
function saveValuesForPersistance() {
	var formPersistanceArray = new Array();
	for (i = 0; i < fieldsArrayAttribute.length; i++) {
		formPersistanceArray[fieldsArrayAttribute[i]] = document.getElementById(fieldsArrayAttribute[i]).value;
	}
	return formPersistanceArray;
}

function recoverValuesFromPersistance(formPersistanceArray) {
	for (i = 0; i < fieldsArrayAttribute.length; i++) {
		 document.getElementById(fieldsArrayAttribute[i]).value = formPersistanceArray[fieldsArrayAttribute[i]];
	}
}

function handleValidationErrors(responseArray) {
	for (var k in responseArray) {
		var elementName = k.charAt(0).toUpperCase() + k.slice(1);
		$("#Attribute" + elementName).parent().addClass("error");
		$("#Attribute" + elementName).parent().append("<div class=\"error-message\">" + responseArray[k] + "</div>");
	}

}