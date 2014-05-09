function deleteObject2(type, id, event) {
	var typeMessage, name, action;
	if (type == 'attributes') {
		action = 'delete';
		typeMessage = 'Attribute';
		name = '#Attribute' + '_' + id + '_delete';
	}
	if (type == 'shadow_attributes') {
		action = 'discard';
		typeMessage = 'Proposal';
		name = '#ShadowAttribute' + '_' + id + '_delete';
	}
	if (confirm("Are you sure you want to delete " + typeMessage + " #" + id + "?")) {
		var formData = $(name).serialize();
		$.ajax({
			data: formData, 
			success:function (data, textStatus) {
				updateAttributeIndexOnSuccess(event);
				handleGenericAjaxResponse(data);
			}, 
			type:"post", 
			cache: false,
			url:"/" + type + "/" + action + "/" + id,
		});
	}	
}

function deleteObject(type, action, id, event) {
	var destination = 'attributes';
	if (type == 'shadow_attributes') destination = 'shadow_attributes';
	$.get( "/" + destination + "/" + action + "/" + id, function(data) {
		$("#confirmation_box").fadeIn();
		$("#gray_out").fadeIn();
		$("#confirmation_box").html(data);
		$(window).bind('keypress', function(e) {
			var code = e.keyCode || e.which;
			if (code == 13) {
				submitDeletion(event, action, type, id);
			}
		});
	});
}

function cancelPrompt() {
	$("#confirmation_box").fadeIn();
	$("#gray_out").fadeOut();
	$("#confirmation_box").empty();
}

function submitDeletion(event, action, type, id) {
	var formData = $('#PromptForm').serialize();
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		data: formData, 
		success:function (data, textStatus) {
			updateAttributeIndexOnSuccess(event);
			handleGenericAjaxResponse(data);
		}, 
		complete:function() {
			$(".loading").hide();
			$("#confirmation_box").fadeOut();
			$("#gray_out").fadeOut();
		},
		type:"post", 
		cache: false,
		url:"/" + type + "/" + action + "/" + id,
	});
}

function acceptObject(type, id, event) {
	name = '#ShadowAttribute_' + id + '_accept';
	var formData = $(name).serialize();
	$.ajax({
		data: formData, 
		success:function (data, textStatus) {
			updateAttributeIndexOnSuccess(event);
			handleGenericAjaxResponse(data);
		}, 
		type:"post", 
		cache: false,
		url:"/shadow_attributes/accept/" + id,
	});
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
	resetForms();
	if (type == 'denyForm') return;
	var objectType = 'attributes';
	if (type == 'ShadowAttribute') {
		objectType = 'shadow_attributes';
	}
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
		url:"/" + objectType + "/fetchEditForm/" + id + "/" + field,
	});
}

//if someone clicks an inactive field, replace it with the hidden form field. Also, focus it and bind a focusout event, so that it gets saved if the user clicks away.
//If a user presses enter, submit the form
function postActivationScripts(name, type, id, field, event) {
	$(name + '_field').focus();
	inputFieldButtonActive(name + '_field');
	if (field == 'value' || field == 'comment') {
		autoresize($(name + '_field')[0]);
		$(name + '_field').on('keyup', function () {
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
	$(selector).closest('.inline-input-container').children('.inline-input-daecline').addClass('inline-input-passive').removeClass('inline-input-active');
}

function autoresize(textarea) {
    textarea.style.height = '20px';
    textarea.style.height = (textarea.scrollHeight) + 'px';
}

// submit the form - this can be triggered by unfocusing the activated form field or by submitting the form (hitting enter)
// after the form is submitted, intercept the response and act on it 
function submitForm(type, id, field, event) {
	var object_type = 'attributes';
	if (type == 'ShadowAttribute') object_type = 'shadow_attributes';
	var name = '#' + type + '_' + id + '_' + field;
	$.ajax({
		data: $(name + '_field').closest("form").serialize(),
		cache: false,
		success:function (data, textStatus) {
			handleAjaxEditResponse(data, name, type, id, field, event);
		}, 
		error:function() {
			showMessage('fail', 'Request failed for an unknown reason.');
			updateAttributeIndexOnSuccess(event);
		},
		type:"post", 
		url:"/" + object_type + "/editField/" + id
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
			handleGenericAjaxResponse(data);
		}, 
		error:function() {
			showMessage('fail', 'Could not add tag.');
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
	if (type == 'Attribute') {
		if (responseArray.saved) {
			showMessage('success', responseArray.success);
			updateAttributeFieldOnSuccess(name, type, id, field, event);
			updateAttributeFieldOnSuccess(name, type, id, 'timestamp', event);
		} else {
			showMessage('fail', 'Validation failed: ' + responseArray.errors.value);
			updateAttributeFieldOnSuccess(name, type, id, field, event);
		}
	}
	if (type == 'ShadowAttribute') {
		updateAttributeIndexOnSuccess(event);
	}
}

function handleGenericAjaxResponse(data) {
	responseArray = JSON.parse(data);
	if (responseArray.saved) {
		showMessage('success', responseArray.success);
	} else {
		showMessage('fail', responseArray.errors);
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
				updateAttributeIndexOnSuccess(event);
				handleGenericAjaxResponse(data);
			}, 
		});
	}
	return false;
}

function editSelectedAttributes(event) {
	$.get("/attributes/editSelected/"+event, function(data) {
		$("#attribute_add_form").fadeIn();
		$("#gray_out").fadeIn();
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
				handleGenericAjaxResponse(data);
			}, 
			complete:function() {
				$(".loading").hide();
			}
		});
	}
	return false;
}

function clickCreateButton(event, type) {
	var destination = 'attributes';
	if (type == 'Proposal') destination = 'shadow_attributes';
	$.get( "/" + destination + "/add/" + event, function(data) {
		$("#attribute_add_form").fadeIn();
		$("#gray_out").fadeIn();
		$("#attribute_add_form").html(data);
	});
}

function submitPopoverForm(event, referer) {
	var url = null;
	if (referer == 'add') url = "/attributes/add/" + event;
	if (referer == 'propose') url = "/shadow_attributes/add/" + event;
	if (referer == 'massEdit') url = "/attributes/editSelected/" + event;
	if (url !== null) {
		$.ajax({
			beforeSend: function (XMLHttpRequest) {
				$(".loading").show();
				$("#gray_out").fadeOut();
				$("#attribute_add_form").fadeOut();
			}, 
			data: $("#submitButton").closest("form").serialize(), 
			success:function (data, textStatus) {
				handleAjaxPopoverResponse(data, event, url, referer);
				$(".loading").show();
			}, 
			type:"post", 
			url:url
		});
	}
};

function handleAjaxPopoverResponse(response, event, url, referer) {
	responseArray = JSON.parse(response);
	var message = null;
	if (responseArray.saved) {
		//if (referer == 'add') message = "Attribute added.";
		//if (referer == 'propose') message = "Proposal added.";
		//if (referer == 'massEdit') message = "Attributes updated.";
		updateAttributeIndexOnSuccess(event);
		if (responseArray.success) {
			showMessage("success", responseArray.success);
		}
		if (responseArray.errors) {
			showMessage("fail", responseArray.errors);
		}
	} else {
		var savedArray = saveValuesForPersistance();
		$.ajax({
			async:true, 
			dataType:"html", 
			success:function (data, textStatus) {
				$("#gray_out").fadeIn();
				$("#attribute_add_form").fadeIn();
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

function toggleHistogramType(type, old) {
	var done = false;
	old.forEach(function(entry) {
		if (type == entry) {
			done = true;
			old.splice(old.indexOf(entry), 1);
		}
	});
	if (done == false) old.push(type);
	updateHistogram(JSON.stringify(old));
}

function updateHistogram(selected) {
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		dataType:"html", 
		cache: false,
		success:function (data, textStatus) {
			$(".loading").hide();
			$("#histogram").html(data);
		}, 
		url:"/users/histogram/" + selected,
	});
}

function showMessage(success, message) {
	$("#ajax_" + success).html(message);
	var duration = 1000 + (message.length * 40);
	$("#ajax_" + success + "_container").fadeIn("slow");
	$("#ajax_" + success + "_container").delay(duration).fadeOut("slow");
}