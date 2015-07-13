String.prototype.ucfirst = function() {
	return this.charAt(0).toUpperCase() + this.slice(1);
}

function deleteObject(type, action, id, event) {
	var destination = 'attributes';
	if (type == 'shadow_attributes') destination = 'shadow_attributes';
	if (type == 'template_elements') destination = 'template_elements';
	$.get( "/" + destination + "/" + action + "/" + id, function(data) {
		$("#confirmation_box").fadeIn();
		$("#gray_out").fadeIn();
		$("#confirmation_box").html(data);
	});
}

function publishPopup(id, type) {
	var action = "alert";
	if (type == "publish") action = "publish";
	var destination = 'attributes';
	$.get( "/events/" + action + "/" + id, function(data) {
		$("#confirmation_box").html(data);
		$("#confirmation_box").fadeIn();
		$("#gray_out").fadeIn();
	});
}

function submitPublish(id, type) {
	$("#PromptForm").submit();
}

function editTemplateElement(type, id) {
	$.get( "/template_elements/edit/" + type + "/" + id, function(data) {
		$("#popover_form").fadeIn();
		$("#gray_out").fadeIn();
		$("#popover_form").html(data);

	});
}

function cancelPrompt() {
	$("#confirmation_box").fadeIn();
	$("#gray_out").fadeOut();
	$("#confirmation_box").empty();
}

function submitDeletion(context_id, action, type, id) {
	var context = 'event';
	if (type == 'template_elements') context = 'template';
	var formData = $('#PromptForm').serialize();
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		data: formData, 
		success:function (data, textStatus) {
			updateIndex(context_id, context);
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

function initiatePasswordReset(id) {
	$.get( "/users/initiatePasswordReset/" + id, function(data) {
		$("#confirmation_box").fadeIn();
		$("#gray_out").fadeIn();
		$("#confirmation_box").html(data);
	});
}

function submitPasswordReset(id) {
	var formData = $('#PromptForm').serialize();
	var url = "/users/initiatePasswordReset/" + id;
	if ($('#firstTime').is(":checked")) url += "/true";
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		data: formData, 
		success:function (data, textStatus) {
			handleGenericAjaxResponse(data);
		}, 
		complete:function() {
			$(".loading").hide();
			$("#confirmation_box").fadeOut();
			$("#gray_out").fadeOut();
		},
		type:"post", 
		cache: false,
		url:url,
	});
}

function acceptObject(type, id, event) {
	name = '#ShadowAttribute_' + id + '_accept';
	var formData = $(name).serialize();
	$.ajax({
		data: formData, 
		success:function (data, textStatus) {
			updateIndex(event, 'event');
			eventUnpublish();
			handleGenericAjaxResponse(data);
		}, 
		type:"post", 
		cache: false,
		url:"/shadow_attributes/accept/" + id,
	});
}	

function eventUnpublish() {
	$('.publishButtons').show();
	$('.exportButtons').hide();
	$('.published').hide();
	$('.notPublished').show();
}

function updateIndex(id, context, newPage) {
	if (typeof newPage !== 'undefined') page = newPage;
	var url, div;
	if (context == 'event') {
		url = "/events/view/" + id + "/attributesPage:" + page;
		div = "#attributes_div";
	}
	if (context == 'template') {
		url = "/template_elements/index/" + id;
		div = "#templateElements";
	}
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		dataType:"html", 
		cache: false,
		success:function (data, textStatus) {
			$(".loading").hide();
			$(div).html(data);
		}, 
		url: url,
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
function submitForm(type, id, field, context) {
	var object_type = 'attributes';
	var action = "editField";
	var name = '#' + type + '_' + id + '_' + field;
	if (type == 'ShadowAttribute') {
		object_type = 'shadow_attributes';
	}
	$.ajax({
		data: $(name + '_field').closest("form").serialize(),
		cache: false,
		success:function (data, textStatus) {
			handleAjaxEditResponse(data, name, type, id, field, context);
		}, 
		error:function() {
			showMessage('fail', 'Request failed for an unknown reason.');
			updateIndex(context, 'event');
		},
		type:"post", 
		url:"/" + object_type + "/" + action + "/" + id
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
			eventUnpublish();
		} else {
			showMessage('fail', 'Validation failed: ' + responseArray.errors.value);
			updateAttributeFieldOnSuccess(name, type, id, field, event);
		}
	}
	if (type == 'ShadowAttribute') {
		updateIndex(event, 'event');
	}
}

function handleGenericAjaxResponse(data) {
	if (typeof data == 'string') {
		responseArray = JSON.parse(data);
	} else {
		responseArray = data;
	}
	if (responseArray.saved) {
		showMessage('success', responseArray.success);
		return true;
	} else {
		showMessage('fail', responseArray.errors);
		return false;
	}
}

function toggleAllAttributeCheckboxes() {
	if ($(".select_all").is(":checked")) {
		$(".select_attribute").prop("checked", true);
		$(".select_proposal").prop("checked", true);
	} else {
		$(".select_attribute").prop("checked", false);
		$(".select_proposal").prop("checked", false);
	}
}

function attributeListAnyAttributeCheckBoxesChecked() {
	if ($('.select_attribute:checked').length > 0) $('.mass-select').show();
	else $('.mass-select').hide();
}

function attributeListAnyProposalCheckBoxesChecked() {
	if ($('.select_proposal:checked').length > 0) $('.mass-proposal-select').show();
	else $('.mass-proposal-select').hide();
}

function multiSelectAction(event, context) {
	var settings = {
			deleteAttributes: {
				confirmation: "Are you sure you want to delete all selected attributes?",
				controller: "attributes",
				camelCase: "Attribute",
				alias: "attribute",
				action: "delete",
			},
			acceptProposals: {
				confirmation: "Are you sure you want to accept all selected proposals?",
				controller: "shadow_attributes",
				camelCase: "ShadowAttribute",
				alias: "proposal",
				action: "accept",
			},
			discardProposals: {
				confirmation: "Are you sure you want to discard all selected proposals?",
				controller: "shadow_attributes",
				camelCase: "ShadowAttribute",
				alias: "proposal",
				action: "discard",
			},
	};
	var answer = confirm("Are you sure you want to " + settings[context]["action"] + " all selected " + settings[context]["alias"] + "s?");
	if (answer) {
		var selected = [];
		$(".select_" + settings[context]["alias"]).each(function() {
			if ($(this).is(":checked")) {
				var temp= $(this).data("id");
				selected.push(temp);
			}
		});
		$('#' + settings[context]["camelCase"] + 'Ids' + settings[context]["action"].ucfirst()).attr('value', JSON.stringify(selected));
		var formData = $('#' + settings[context]["action"] + '_selected').serialize();
		$.ajax({
			data: formData, 
			cache: false,
			type:"POST", 
			url:"/" + settings[context]["controller"] + "/" + settings[context]["action"] + "Selected/" + event,
			success:function (data, textStatus) {
				updateIndex(event, 'event');
				var result = handleGenericAjaxResponse(data);
				if (settings[context]["action"] != "discard" && result == true) eventUnpublish(); 
			}, 
		});
	}
	return false;
}

function editSelectedAttributes(event) {
	$.get("/attributes/editSelected/"+event, function(data) {
		$("#popover_form").fadeIn();
		$("#gray_out").fadeIn();
		$("#popover_form").html(data);
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
		$("#popover_form").fadeIn();
		$("#gray_out").fadeIn();
		$("#popover_form").html(data);
	});
}

function submitPopoverForm(context_id, referer, update_context_id) {
	var url = null;
	var context = 'event';
	var contextNamingConvention = 'Attribute';
	switch (referer) {
		case 'add': 
			url = "/attributes/add/" + context_id;
			break;
		case 'propose':
			url = "/shadow_attributes/add/" + context_id;
			break;
		case 'massEdit':
			url = "/attributes/editSelected/" + context_id;
			break;
		case 'addTextElement':
			url = "/templateElements/add/text/" + context_id;
			context = 'template';
			contextNamingConvention = 'TemplateElementText';
			break;
		case 'editTextElement':
			url = "/templateElements/edit/text/" + context_id;
			context = 'template';
			context_id = update_context_id;
			contextNamingConvention = 'TemplateElementText';
			break;
		case 'addAttributeElement':
			url = "/templateElements/add/attribute/" + context_id;
			context = 'template';
			contextNamingConvention = 'TemplateElementAttribute';
			break;
		case 'editAttributeElement':
			url = "/templateElements/edit/attribute/" + context_id;
			context = 'template';
			context_id = update_context_id;
			contextNamingConvention = 'TemplateElementAttribute';
			break;
		case 'addFileElement':
			url = "/templateElements/add/file/" + context_id;
			context = 'template';
			contextNamingConvention = 'TemplateElementFile';
			break;
		case 'editFileElement':
			url = "/templateElements/edit/file/" + context_id;
			context = 'template';
			context_id = update_context_id;
			contextNamingConvention = 'TemplateElementFile';
			break;
		case 'replaceAttributes':
			url = "/attributes/attributeReplace/" + context_id;
			break;
	}
	
	if (url !== null) {
		$.ajax({
			beforeSend: function (XMLHttpRequest) {
				$(".loading").show();
				$("#gray_out").fadeOut();
				$("#popover_form").fadeOut();
			}, 
			data: $("#submitButton").closest("form").serialize(), 
			success:function (data, textStatus) {
				var result = handleAjaxPopoverResponse(data, context_id, url, referer, context, contextNamingConvention);
				if (context == 'event' && (referer == 'add' || referer == 'massEdit' || referer == 'replaceAttributes')) eventUnpublish();
				$(".loading").show();
			}, 
			type:"post", 
			url:url
		});
		$("#popover_form").empty();
	}
};

function handleAjaxPopoverResponse(response, context_id, url, referer, context, contextNamingConvention) {
	responseArray = JSON.parse(response);
	var message = null;
	if (responseArray.saved) {
		updateIndex(context_id, context);
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
				$("#popover_form").fadeIn();
				$("#popover_form").html(data);
				var error_context = context.charAt(0).toUpperCase() + context.slice(1);
				handleValidationErrors(responseArray.errors, context, contextNamingConvention);
				if (!isEmpty(responseArray)) {
					$("#formWarning").show();
					$("#formWarning").html('The object(s) could not be saved. Please, try again.');
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
	for (i = 0; i < fieldsArray.length; i++) {
		formPersistanceArray[fieldsArray[i]] = document.getElementById(fieldsArray[i]).value;
	}
	return formPersistanceArray;
}

function recoverValuesFromPersistance(formPersistanceArray) {
	for (i = 0; i < fieldsArray.length; i++) {
		 document.getElementById(fieldsArray[i]).value = formPersistanceArray[fieldsArray[i]];
	}
}

function handleValidationErrors(responseArray, context, contextNamingConvention) {
	for (var k in responseArray) {
		var elementName = k.charAt(0).toUpperCase() + k.slice(1);
		$("#" + contextNamingConvention + elementName).parent().addClass("error");
		$("#" + contextNamingConvention + elementName).parent().append("<div class=\"error-message\">" + responseArray[k] + "</div>");
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

function showMessage(success, message, context) {
	if (typeof context !== "undefined") {
		$("#ajax_" + success, window.parent.document).html(message);
		var duration = 1000 + (message.length * 40);
		$("#ajax_" + success + "_container", window.parent.document).fadeIn("slow");
		$("#ajax_" + success + "_container", window.parent.document).delay(duration).fadeOut("slow");
	}
	$("#ajax_" + success).html(message);
	var duration = 1000 + (message.length * 40);
	$("#ajax_" + success + "_container").fadeIn("slow");
	$("#ajax_" + success + "_container").delay(duration).fadeOut("slow");
}

function cancelPopoverForm() {
	$("#popover_form").empty();
	$('#gray_out').fadeOut();
	$('#popover_form').fadeOut();
}

function activateTagField() {
	$("#addTagButton").hide();
	$("#addTagField").show();
}

function tagFieldChange() {
	if ($("#addTagField :selected").val() > 0) {
		var selected = $("#addTagField :selected").text();
		if ($.inArray(selected, selectedTags)==-1) {
			selectedTags.push(selected);
			appendTemplateTag(selected);
		}
	}
	$("#addTagButton").show();
	$("#addTagField").hide();
}

function appendTemplateTag(selected) {
	var selectedTag;
	allTags.forEach(function(tag) {
		if (tag.name == selected) {
			$.ajax({
				beforeSend: function (XMLHttpRequest) {
					$(".loading").show();
				}, 
				dataType:"html", 
				cache: false,
				success:function (data, textStatus) {
					$(".loading").hide();
					$("#tags").append(data);
				}, 
				url:"/tags/viewTag/" + tag.id,
			});
			updateSelectedTags();
		}
	});
}

function addAllTags(tagArray) {
	parsedTagArray = JSON.parse(tagArray);
	parsedTagArray.forEach(function(tag) {
		appendTemplateTag(tag);
	});
}

function removeTemplateTag(id, name) {
	selectedTags.forEach(function(tag) {
		if (tag == name) {
			var index = selectedTags.indexOf(name);
			if (index > -1) {
				selectedTags.splice(index, 1);
				updateSelectedTags();
			}
		}
	});
	$('#tag_bubble_' + id).remove();
}

function updateSelectedTags() {
	$('#hiddenTags').attr("value", JSON.stringify(selectedTags));
}

function saveElementSorting(order) {
	$.ajax({
		data: order, 
		dataType:"json",
		contentType: "application/json",
		cache: false,
		success:function (data, textStatus) {
			handleGenericAjaxResponse(data);
		}, 
		type:"post", 
		cache: false,
		url:"/templates/saveElementSorting/",
	});
}

function templateAddElementClicked(id) {
	$("#gray_out").fadeIn();
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		dataType:"html", 
		cache: false,
		success:function (data, textStatus) {
			$(".loading").hide();
			$("#popover_form").html(data);
			$("#popover_form").fadeIn();
		}, 
		url:"/template_elements/templateElementAddChoices/" + id,
	});
}

function templateAddElement(type, id) {
	$.ajax({
		dataType:"html", 
		cache: false,
		success:function (data, textStatus) {
			$("#popover_form").html(data);
		}, 
		url:"/template_elements/add/" + type + "/" + id,
	});
}

function templateUpdateAvailableTypes() {
	$("#innerTypes").empty();
	var type = $("#TemplateElementAttributeType option:selected").text();
	var complex = $('#TemplateElementAttributeComplex:checked').val();
	if (complex && type != 'Select Type') {
		currentTypes.forEach(function(entry) {
			$("#innerTypes").append("<div class=\"templateTypeBox\" id=\"" + entry + "TypeBox\">" + entry + "</div>");
		});
		$('#outerTypes').show();
	}
	else $('#outerTypes').hide();
}

function populateTemplateTypeDropdown() {
	var cat = $("#TemplateElementAttributeCategory option:selected").text();
	currentTypes = [];
	if (cat == 'Select Category') {
		$('#TemplateElementAttributeType').html("<option>Select Type</option>");
	} else {
		var complex = $('#TemplateElementAttributeComplex:checked').val();
		if (cat in typeGroupCategoryMapping) {
			$('#TemplateElementAttributeType').html("<option>Select Type</option>");
			typeGroupCategoryMapping[cat].forEach(function(entry) {
				$('#TemplateElementAttributeType').append("<option>" + entry + "</option>");
			});
		} else {
			complex = false;
		}
		if (!complex) {
			$('#TemplateElementAttributeType').html("<option>Select Type</option>");
			categoryTypes[cat].forEach(function(entry) {
				$('#TemplateElementAttributeType').append("<option>" + entry + "</option>");
			});
		}
	}
}

function templateElementAttributeTypeChange() {
	var complex = $('#TemplateElementAttributeComplex:checked').val();
	var type = $("#TemplateElementAttributeType option:selected").text();
	currentTypes = [];
	if (type != 'Select Type') {
		if (complex) {
			complexTypes[type]["types"].forEach(function(entry) {
				currentTypes.push(entry);
			});
		} else {
			currentTypes.push(type);
		}
	} else {
		currentTypes = [];
	}
	$("#typeJSON").html(JSON.stringify(currentTypes));
	templateUpdateAvailableTypes();
}

function templateElementAttributeCategoryChange(category) {
	if (category in typeGroupCategoryMapping) {
		$('#complexToggle').show();
	} else {
		$('#complexToggle').hide();
	}
	if (category != 'Select Type') {
		populateTemplateTypeDropdown();
	}
	templateUpdateAvailableTypes();
}

function templateElementFileCategoryChange(category) {
	if (category == '') {
		$("#TemplateElementFileMalware")[0].disabled = true;
		$("#TemplateElementFileMalware")[0].checked = false;
	} else {
		if (categoryArray[category].length == 2) {
			$("#TemplateElementFileMalware")[0].disabled = false;
			$("#TemplateElementFileMalware")[0].checked = true;
		} else {
			$("#TemplateElementFileMalware")[0].disabled = true;
			if (categoryArray[category] == 'attachment') $("#TemplateElementFileMalware")[0].checked = false;
			else $("#TemplateElementFileMalware")[0].checked = true;
		}
	}
}

function getPopup(id, context, target) {
	$("#gray_out").fadeIn();
	var url = "";
	if (context != '') url += "/" + context;
	if (target != '') url += "/" + target;
	if (id != '') url += "/" + id;
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		dataType:"html", 
		cache: false,
		success:function (data, textStatus) {
			$(".loading").hide();
			$("#popover_form").html(data);
			$("#popover_form").fadeIn();
		}, 
		url: url,
		//url:"/templates/templateChoices/" + id,
	});
}

function resizePopoverBody() {
	var bodyheight = $(window).height();
	bodyheight = 3 * bodyheight / 4 - 150;
	$("#popover_choice_main").css({"max-height": bodyheight});
}

function populateTemplateHiddenFileDiv(files) {
	$('#TemplateFileArray').val(JSON.stringify(files));
}

function populateTemplateFileBubbles() {
	var fileObjectArray = JSON.parse($('#TemplateFileArray').val());
	fileObjectArray.forEach(function(entry) {
		templateAddFileBubble(entry.element_id, false, entry.filename, entry.tmp_name, 'yes');
	});
}

function templateFileHiddenAdd(files, element_id, batch) {
	var fileArray = $.parseJSON($('#TemplateFileArray', window.parent.document).val());
	var contained = false;
	for (var j=0; j< files.length; j++) {
		for (var i=0; i< fileArray.length; i++) {
			if (fileArray[i].filename == files[j].filename) {
				contained = true;
			}
			if (batch == 'no' && fileArray[i].element_id == element_id) {
				templateDeleteFileBubble(fileArray[i].filename, fileArray[i].tmp_name, fileArray[i].element_id, 'iframe', batch);
				contained = false;
				var removeId = i;
			}
		}
		if (batch == 'no') fileArray.splice(removeId, 1);
		if (contained == false) {
			fileArray.push(files[j]);
			templateAddFileBubble(element_id, true, files[j].filename, files[j].tmp_name, batch);
			$('#TemplateFileArray', window.parent.document).val(JSON.stringify(fileArray));
		}
	}
}

function htmlEncode(value){
	return $('<div/>').text(value).html();
}

function templateAddFileBubble(element_id, iframe, filename, tmp_name, batch) {
	filename = htmlEncode(filename);
	tmp_name = htmlEncode(tmp_name);
	if (batch == 'no') {
		if (iframe == true) {
			$('#filenames_' + element_id, window.parent.document).html('<div id ="' + tmp_name + '_container" class ="template_file_box_container"><span class="tagFirstHalf template_file_box">' + filename + '</span><span onClick="templateDeleteFileBubble(\'' + filename + '\', \'' + tmp_name + '\', \'' + element_id + '\', \'normal\', \'no\');" class="tagSecondHalf useCursorPointer">x</span></div>');
		} else {
			$('#filenames_' + element_id).html('<div id ="' + tmp_name + '_container" class ="template_file_box_container"><span class="tagFirstHalf template_file_box">' + filename + '</span><span onClick="templateDeleteFileBubble(\'' + filename + '\', \'' + tmp_name + '\', \'' + element_id + '\', \'normal\', \'no\');" class="tagSecondHalf useCursorPointer">x</span></div>');
		}
	} else {
		if (iframe == true) {
			$('#filenames_' + element_id, window.parent.document).append('<div id ="' + tmp_name + '_container" class ="template_file_box_container"><span class="tagFirstHalf template_file_box">' + filename + '</span><span onClick="templateDeleteFileBubble(\'' + filename + '\', \'' + tmp_name + '\', \'' + element_id + '\', \'normal\', \'yes\');" class="tagSecondHalf useCursorPointer">x</span></div>');
		} else {
			$('#filenames_' + element_id).append('<div id ="' + tmp_name + '_container" class ="template_file_box_container"><span class="tagFirstHalf template_file_box">' + filename + '</span><span onClick="templateDeleteFileBubble(\'' + filename + '\', \'' + tmp_name + '\', \'' + element_id + '\', \'normal\', \'yes\');" class="tagSecondHalf useCursorPointer">x</span></div>');
		}
	}
}

function templateDeleteFileBubble(filename, tmp_name, element_id, context, batch) {
	$(".loading").show();
	$.ajax({
		type:"post", 
		cache: false,
		url:"/templates/deleteTemporaryFile/" + tmp_name,
	});
	var c = this;
	if (context == 'iframe') {
		$('#' + tmp_name + '_container', window.parent.document).remove();
		var oldArray = JSON.parse($('#TemplateFileArray', window.parent.document).val());
	} else {
		$('#' + tmp_name + '_container').remove();
		var oldArray = JSON.parse($('#TemplateFileArray').val());
	}
	var newArray = [];
	oldArray.forEach(function(entry) {
		if (batch == 'no') {
			if (entry.element_id != element_id) {
				newArray.push(entry);
			}
		} else {
			if (entry.tmp_name != tmp_name) {
				newArray.push(entry);
			}
		}
	}); 
	if (batch == 'no') {
		$('#fileUploadButton_' + element_id, $('#iframe_' + element_id).contents()).html('Upload File');
	}
	if (context == 'iframe') {
		$('#TemplateFileArray', window.parent.document).val(JSON.stringify(newArray));
	} else {
		$('#TemplateFileArray').val(JSON.stringify(newArray));
	}
	$(".loading").hide();
}
	
function templateFileUploadTriggerBrowse(id) {
	$('#upload_' + id + '_file').click();
}

function freetextRemoveRow(id, event_id) {
	$('#row_' + id).hide();
	$('#Attribute' + id + 'Save').attr("value", "0");
	if ($(".freetext_row:visible").length == 0) {
		window.location = "/events/" + event_id;
	}
}

function indexEvaluateFiltering() {
	if (filterContext == "event") {
		if (filtering.published != 2) {
			$('#value_published').html(publishedOptions[filtering.published]);
		} else {
			$('#value_published').html("");
		}
		if (filtering.date.from != null || filtering.date.from != null) {
			var text = "";
			if (filtering.date.from != "") text = "From: " + filtering.date.from;
			if (filtering.date.until != "") {
				if (text != "") text += " ";
				text += "Until: " + filtering.date.until;
			}
		}
		$('#value_date').html(text);
		for (var i = 0; i < simpleFilters.length; i++) {
			indexEvaluateSimpleFiltering(simpleFilters[i]);
		}
		indexRuleChange();
	} else {
		for (var i = 0; i < differentFilters.length; i++) {
			if (filtering[differentFilters[i]] != "") {
				var text = "";
				if (filtering[differentFilters[i]] == 1) text = "Yes";
				else if (filtering[differentFilters[i]] == 0) text = "No";
				$('#value_' + differentFilters[i]).html(text);
			} else {
				$('#value_' + differentFilters[i]).html("");
			}
		}
		for (var i = 0; i < simpleFilters.length; i++) {
			indexEvaluateSimpleFiltering(simpleFilters[i]);
		}
	}
	indexSetTableVisibility();
	indexSetRowVisibility();
	$('#generatedURLContent').html(indexCreateFilters());
}

function quickFilterEvents(passedArgs) {
	passedArgs["searchall"] = $('#quickFilterField').val();
	var url = "/events/index";
	for (var key in passedArgs) {
		url += "/" + key + ":" + passedArgs[key];
	}
	window.location.href=url;
}

$('#quickFilterField').bind("enterKey",function(e){
	$('#quickFilterButton').trigger("click");
});
$('#quickFilterField').keyup(function(e){
	if(e.keyCode == 13)
	{
    	$('#quickFilterButton').trigger("click");
	}
});
	
function indexApplyFilters() {
	var url = indexCreateFilters();
	window.location.href = url;
}

function indexCreateFilters() {
	text = "";
	if (filterContext == 'event') {
		if (filtering.published != "2") {
			text += "searchpublished:" + filtering.published;
		}
	} else {
		for (var i = 0; i < differentFilters.length; i++) {
			if (filtering[differentFilters[i]]) {
				if (text != "") text += "/";
				text += "search" + differentFilters[i] + ":" + filtering[differentFilters[i]];
			}
		}
	}
	for (var i = 0; i < simpleFilters.length; i++) {
		text = indexBuildArray(simpleFilters[i], text);
	}
	if (filterContext == 'event') {
		if (filtering.date.from) {
			if (text != "") text += "/";
			text += "searchDatefrom:" + filtering.date.from; 
		}
		if (filtering.date.until) {
			if (text != "") text += "/";
			text += "searchDateuntil:" + filtering.date.until;
		}
		return baseurl + '/events/index/' + text;
	} else {
		return baseurl + '/admin/users/index/' + text;
	}
}

function indexBuildArray(type, text) {
	temp = "";
	if (text != "") temp += "/";
	temp += "search" + type + ":";
	if (filtering[type].NOT.length == 0 && filtering[type].OR.length == 0) return text;
	var swap = filtering[type].OR.length;
	var temp_array = filtering[type].OR.concat(filtering[type].NOT);
	for (var i = 0; i < temp_array.length; i++) {
		if (i > 0) temp += "|";
		if (i >= swap) temp +="!";
		temp += temp_array[i];
	}
	text += temp;
	return text;
}

function indexSetRowVisibility() {
	for (var i = 0; i < allFields.length; i++) {
		if ($("#value_" + allFields[i]).text().trim() != "") {
			$("#row_" + allFields[i]).show();
		} else {
			$("#row_" + allFields[i]).hide();
		}
	}
}

function indexEvaluateSimpleFiltering(field) {
	text = "";
	if (filtering[field].OR.length == 0 && filtering[field].NOT.length == 0) {
		$('#value_' + field).html(text);
		return false;
	}
	if (filtering[field].OR.length !=0) {
		for (var i = 0; i < filtering[field].OR.length; i++) {
			if (i > 0) text += '<span class="green bold"> OR </span>';
			if (typedFields.indexOf(field) == -1) {
				text += filtering[field].OR[i];		
			} else {
				for (var j = 0; j < typeArray[field].length; j++) {
					if (typeArray[field][j].id == filtering[field].OR[i]) {
						text += typeArray[field][j].value;
					}
				}
			}
		} 
	}
	if (filtering[field].NOT.length !=0) {
		for (var i = 0; i < filtering[field].NOT.length; i++) {
			if (i == 0) {
				if (text != "") text += '<span class="red bold"> AND NOT </span>';
				else text += '<span class="red bold">NOT </span>';
			} else text += '<span class="red bold"> AND NOT </span>';
			if (typedFields.indexOf(field) == -1) {
				text += filtering[field].NOT[i];	
			} else {
				for (var j = 0; j < typeArray[field].length; j++) {
					if (typeArray[field][j].id == filtering[field].NOT[i]) {
						text += typeArray[field][j].value;
					}
				}
			}
		} 
	}
	$('#value_' + field).html(text);
}

function indexAddRule(param) {
	var found = false;
	if (filterContext == 'event') {
		if (param.data.param1 == "date") {
			var val1 = escape($('#EventSearch' + param.data.param1 + 'from').val());
			var val2 = escape($('#EventSearch' + param.data.param1 + 'until').val());
			if (val1 != "") filtering.date.from = val1;
			if (val2 != "") filtering.date.until = val2;
		} else if (param.data.param1 == "published") {
			var value = escape($('#EventSearchpublished').val());
			if (value != "") filtering.published = value;
		} else {
			var value = escape($('#EventSearch' + param.data.param1).val());
			var operator = operators[escape($('#EventSearchbool').val())];
			if (value != "" && filtering[param.data.param1][operator].indexOf(value) < 0) filtering[param.data.param1][operator].push(value);
		}
	} else if (filterContext = 'user') {
		if (differentFilters.indexOf(param.data.param1) != -1) {
			var value = escape($('#UserSearch' + param.data.param1).val());
			if (value != "") filtering[param.data.param1] = value;
		} else {
			var value = escape($('#UserSearch' + param.data.param1).val());
			var operator = operators[escape($('#UserSearchbool').val())];
			if (value != "" && filtering[param.data.param1][operator].indexOf(value) < 0) filtering[param.data.param1][operator].push(value);
		}
	}
	indexEvaluateFiltering();
}

function indexSetTableVisibility() {
	var visible = false;
	if ($("[id^='value_']").text().trim()!="" && $("[id^='value_']").text().trim()!="-1") {
		visible = true;
	}
	if (visible == true) $('#FilterplaceholderTable').hide();
	else $('#FilterplaceholderTable').show();
}

function indexRuleChange() {
	var context = filterContext.charAt(0).toUpperCase() + filterContext.slice(1);
	$('[id^=' + context + 'Search]').hide();
	var rule = $('#' + context + 'Rule').val();
	var fieldName = '#' + context + 'Search' + rule;
	if (fieldName == '#' + context + 'Searchdate') {
		$(fieldName + 'from').show();
		$(fieldName + 'until').show();
	} else {
		$(fieldName).show();
	}
	if (simpleFilters.indexOf(rule) != -1) {
		$('#' + context + 'Searchbool').show();
	} else $('#' + context + 'Searchbool').hide();
	
	$('#addRuleButton').show();
	$('#addRuleButton').unbind("click");
	$('#addRuleButton').click({param1: rule}, indexAddRule);
}

function indexFilterClearRow(field) {
	$('#value_' + field).html("");
	$('#row_' + field).hide();
	if (field == "date") {
		filtering.date.from = "";
		filtering.date.until = "";
	} else if (field == "published") {
		filtering.published = 2;
	} else if (differentFilters.indexOf(field) != -1) {
		filtering[field] = "";
	} else {
		filtering[field].NOT = [];
		filtering[field].OR = [];
	}
	indexSetTableVisibility();
	indexEvaluateFiltering();
}


function restrictEventViewPagination() {
	var showPages = new Array();
	var start;
	var end;
	var i;

	if (page < 6) {
		start = 1;
		if (count - page < 6) {
			end = count;
		} else {
			end = page + (9 - (page - start));
		}
	} else if (count - page < 6) {
		end = count;
		start = count - 10;
	} else {
		start = page-5;
		end = page+5;
	}
	
	if (start > 2) {
		$("#apage" + start).parent().before("<li><a href id='aExpandLeft'>...</a></li>");
		$("#aExpandLeft").click(function() {expandPagination(0, 0); return false;});
		$("#bpage" + start).parent().before("<li><a href id='bExpandLeft'>...</a></li>");
		$("#bExpandLeft").click(function() {expandPagination(1, 0); return false;})
	}

	if (end < (count - 1)) {
		$("#apage" + end).parent().after("<li><a href id='aExpandRight'>...</a></li>");
		$("#aExpandRight").click(function() {expandPagination(0, 1); return false;});
		$("#bpage" + end).parent().after("<li><a href id='bExpandRight'>...</a></li>");
		$("#bExpandRight").click(function() {expandPagination(1, 1); return false;})
	}
	
	for (i = 1; i < (count+1); i++) {
		if (i != 1 && i != count && (i < start || i > end)) {
			$("#apage" + i).hide();
			$("#bpage" + i).hide();
		}	
	}
}

function expandPagination(bottom, right) {
	var i;
	var prefix = "a";
	if (bottom == 1) prefix = "b";
	var start = 1;
	var end = page;
	if (right == 1) {
		start = page;
		end = count;
		$("#" + prefix + "ExpandRight").remove();
	} else $("#" + prefix + "ExpandLeft").remove();
	for (i = start; i < end; i++) {
		$("#" + prefix + "page" + i).show();
	}
}

function serverSettingsActivateField(setting, id) {
	resetForms();
	$('.inline-field-placeholder').hide();
	var fieldName = "#setting_" + id; 
	$.ajax({
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		dataType:"html", 
		cache: false,
		success:function (data, textStatus) {
			$(".loading").hide();
			$(fieldName + "_placeholder").html(data);
			$(fieldName + "_solid").hide();
			$(fieldName + "_placeholder").show();
			serverSettingsPostActivationScripts(fieldName, setting, id);
		}, 
		url:"/servers/serverSettingsEdit/" + setting + "/" + id,
	});
}

function serverSettingsPostActivationScripts(name, setting, id) {
	$(name + '_field').focus();
	inputFieldButtonActive(name + '_field');

	$(name + '_form').submit(function(e){ 
		e.preventDefault();
		serverSettingSubmitForm(name, setting, id);
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
			serverSettingSubmitForm(name, setting, id);
		}
	});
	$(name + '_field').closest('.inline-input-container').children('.inline-input-accept').bind('click', function() {
		serverSettingSubmitForm(name, setting, id);
	});
	$(name + '_field').closest('.inline-input-container').children('.inline-input-decline').bind('click', function() {
		resetForms();
		$('.inline-field-placeholder').hide();
	});

	$(name + '_solid').hide();
}

function serverSettingSubmitForm(name, setting, id) {
	var name = '#setting_' + id;
	var formData = $(name + '_field').closest("form").serialize();
	$.ajax({
		data: formData,
		cache: false,
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		success:function (data, textStatus) {
			$.ajax({
				type:"get",
				url:"/servers/serverSettingsReloadSetting/" + setting + "/" + id,
				success:function (data2, textStatus2) {
					$('#' + id + '_row').replaceWith(data2);
					$(".loading").hide();
				},
				error:function() {
					showMessage('fail', 'Could not refresh the table.');
				}
			});
		}, 
		error:function() {
			showMessage('fail', 'Request failed for an unknown reason.');
			resetForms();
			$('.inline-field-placeholder').hide();
		},
		type:"post", 
		url:"/servers/serverSettingsEdit/" + setting + "/" + id + "/" + 1
	});
	$(name + '_field').unbind("keyup");
	$(name + '_form').unbind("focusout");
	return false;
}

function changeFreetextImportFrom() {
	$('#changeTo').find('option').remove();
	options[$('#changeFrom').val()].forEach(function(element) {
		$('#changeTo').append('<option value="' + element + '">' + element + '</option>');
	});
}

function changeFreetextImportCommentExecute() {
	$('.freetextCommentField').val($('#changeComments').val());
}

function changeFreetextImportExecute() {
	var from = $('#changeFrom').val();
	var to = $('#changeTo').val();
	$('.typeToggle').each(function() {
		if ($( this ).val() == from) {
			if (selectContainsOption("#" + $(this).attr('id'), to)) $( this ).val(to);
		}
	});
}

function selectContainsOption(selectid, value) {
	var exists = false;
	$(selectid + ' option').each(function(){
	    if (this.value == value) {
	        exists = true;
	        return false;
	    }
	});
	return exists;
}

function exportChoiceSelect(url, elementId, checkbox) {
	if (checkbox == 1) {
		if ($('#' + elementId + '_toggle').prop('checked')) {
			url = url + $('#' + elementId + '_set').html();
		}
	}
	document.location.href = url;
}

function freetextImportResultsSubmit(id, count) {
	var attributeArray = [];
	var temp;
	for (i = 0; i < count; i++) {
		if ($('#Attribute' + i + 'Save').val() == 1) {
				temp = {
					value:$('#Attribute' + i + 'Value').val(),
					category:$('#Attribute' + i + 'Category').val(),
					type:$('#Attribute' + i + 'Type').val(),
					to_ids:$('#Attribute' + i + 'To_ids')[0].checked,
					comment:$('#Attribute' + i + 'Comment').val(),
				}
				attributeArray[attributeArray.length] = temp;		
		}
	}
	$("#AttributeJsonObject").val(JSON.stringify(attributeArray));
	var formData = $("#AttributeFreeTextImportForm").serialize();
	$.ajax({
		type: "post",
		cache: false,
		url: "/events/saveFreeText/" + id,
		data: formData,
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		},
		success:function (data, textStatus) {
			window.location = '/events/view/' + id;
		}, 
		complete:function() {
			$(".loading").hide();
		},
	});
}

function pgpChoiceSelect(uri) {
	$("#popover_form").fadeOut();
	$("#gray_out").fadeOut();
	$.ajax({
		type: "get",
		url: "https://pgp.mit.edu/" + uri,
		success: function (data) {
			var result = data.split("<pre>")[1].split("</pre>")[0];
			$("#UserGpgkey").val(result);
			showMessage('success', "Key found!");
		},
		error: function (data, textStatus, errorThrown) {
			showMessage('fail', textStatus + ": " + errorThrown);
		}
	});
}

function lookupPGPKey(emailFieldName) {
	$.ajax({
		type: "get",
		url: "/users/fetchPGPKey/" + $('#' + emailFieldName).val(),
		success: function (data) {
			$("#popover_form").fadeIn();
			$("#gray_out").fadeIn();
			$("#popover_form").html(data);
		},
		error: function (data, textStatus, errorThrown) {
			showMessage('fail', textStatus + ": " + errorThrown);
		}
	});
}

function zeroMQServerAction(action) {
	$.ajax({
		type: "get",
		url: "/servers/" + action + "ZeroMQServer/",
		beforeSend: function (XMLHttpRequest) {
			$(".loading").show();
		}, 
		success: function (data) {
			$(".loading").hide();
			if (action !== 'status') {
				window.location.reload();
			} else {
				$("#confirmation_box").html(data);
				$("#confirmation_box").fadeIn();
				$("#gray_out").fadeIn();
			}
		},
		error: function (data, textStatus, errorThrown) {
			showMessage('fail', textStatus + ": " + errorThrown);
		}
	});
}
