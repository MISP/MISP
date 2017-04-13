(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
"use strict";

window.MISPUI = require("./misp-ui");

var functions = Object.keys(MISPUI);
for (var func in functions) {
    var funcName = functions[func];
    window[funcName] = MISPUI[funcName];
}

},{"./misp-ui":2}],2:[function(require,module,exports){
'use strict';

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

require("jquery-ui/ui/widgets/datepicker");

var MISPUI = window.MISPUI || {};

String.prototype.ucfirst = function () {
	return this.charAt(0).toUpperCase() + this.slice(1);
};

module.exports.deleteObject = function (type, action, id, event) {
	var destination = 'attributes';
	var alternateDestinations = ['shadow_attributes', 'template_elements', 'taxonomies'];
	if (alternateDestinations.indexOf(type) > -1) destination = type;
	url = "/" + destination + "/" + action + "/" + id;
	$.get(url, function (data) {
		openPopup("#confirmation_box");
		$("#confirmation_box").html(data);
	});
};

module.exports.quickDeleteSighting = function (id, rawId, context) {
	url = "/sightings/quickDelete/" + id + "/" + rawId + "/" + context;
	$.get(url, function (data) {
		$("#confirmation_box").html(data);
		openPopup("#confirmation_box");
	});
};

module.exports.publishPopup = function (id, type) {
	var action = "alert";
	if (type == "publish") action = "publish";
	var destination = 'attributes';
	$.get("/events/" + action + "/" + id, function (data) {
		$("#confirmation_box").html(data);
		openPopup("#confirmation_box");
	});
};

module.exports.delegatePopup = function (id) {
	simplePopup("/event_delegations/delegateEvent/" + id);
};

module.exports.genericPopup = function (url, popupTarget) {
	$.get(url, function (data) {
		$(popupTarget).html(data);
		$(popupTarget).fadeIn();
		left = $(window).width() / 2 - $(popupTarget).width() / 2;
		$(popupTarget).css({ 'left': left + 'px' });
		$("#gray_out").fadeIn();
	});
};

module.exports.screenshotPopup = function (screenshotData, title) {
	popupHtml = '<img src="' + screenshotData + '" id="screenshot-image" title="' + title + '" />';
	popupHtml += '<div class="close-icon useCursorPointer" onClick="closeScreenshot();"></div>';
	$('#screenshot_box').html(popupHtml);
	$('#screenshot_box').show();
	left = $(window).width() / 2 - $('#screenshot-image').width() / 2;
	$('#screenshot_box').css({ 'left': left + 'px' });
	$("#gray_out").fadeIn();
};

module.exports.submitPublish = function (id, type) {
	$("#PromptForm").submit();
};

module.exports.editTemplateElement = function (type, id) {
	simplePopup("/template_elements/edit/" + type + "/" + id);
};

module.exports.cancelPrompt = function (isolated) {
	if (isolated == undefined) {
		$("#gray_out").fadeOut();
	}
	$("#confirmation_box").fadeOut();
	$("#confirmation_box").empty();
};

module.exports.submitDeletion = function (context_id, action, type, id) {
	var context = 'event';
	if (type == 'template_elements') context = 'template';
	var formData = $('#PromptForm').serialize();
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		data: formData,
		success: function success(data, textStatus) {
			updateIndex(context_id, context);
			handleGenericAjaxResponse(data);
		},
		complete: function complete() {
			$(".loading").hide();
			$("#confirmation_box").fadeOut();
			$("#gray_out").fadeOut();
		},
		type: "post",
		cache: false,
		url: "/" + type + "/" + action + "/" + id
	});
};

module.exports.removeSighting = function (id, rawid, context) {
	if (context != 'attribute') {
		context = 'event';
	}
	var formData = $('#PromptForm').serialize();
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		data: formData,
		success: function success(data, textStatus) {
			handleGenericAjaxResponse(data);
		},
		complete: function complete() {
			$(".loading").hide();
			$("#confirmation_box").fadeOut();
			var org = "/" + $('#org_id').text();
			updateIndex(id, 'event');
			$.get("/sightings/listSightings/" + rawid + "/" + context + org, function (data) {
				$("#sightingsData").html(data);
			});
		},
		type: "post",
		cache: false,
		url: "/sightings/quickDelete/" + id + "/" + rawid + "/" + context
	});
};

module.exports.toggleSetting = function (e, setting, id) {
	e.preventDefault();
	e.stopPropagation();
	switch (setting) {
		case 'warninglist_enable':
			formID = '#WarninglistIndexForm';
			dataDiv = '#WarninglistData';
			replacementForm = '/warninglists/getToggleField/';
			searchString = 'enabled';
			break;
		case 'favourite_tag':
			formID = '#FavouriteTagIndexForm';
			dataDiv = '#FavouriteTagData';
			replacementForm = '/favourite_tags/getToggleField/';
			searchString = 'Adding';
			break;
	}
	$(dataDiv).val(id);
	var formData = $(formID).serialize();
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		data: formData,
		success: function success(data, textStatus) {
			var result = JSON.parse(data);
			if (result.success) {
				var setting = false;
				if (result.success.indexOf(searchString) > -1) setting = true;
				$('#checkBox_' + id).prop('checked', setting);
			}
			handleGenericAjaxResponse(data);
		},
		complete: function complete() {
			$.get(replacementForm, function (data) {
				$('#hiddenFormDiv').html(data);
			});
			$(".loading").hide();
			$("#confirmation_box").fadeOut();
			$("#gray_out").fadeOut();
		},
		error: function error() {
			handleGenericAjaxResponse({ 'saved': false, 'errors': ['Request failed due to an unexpected error.'] });
		},
		type: "post",
		cache: false,
		url: $(formID).attr('action')
	});
};

module.exports.initiatePasswordReset = function (id) {
	$.get("/users/initiatePasswordReset/" + id, function (data) {
		$("#confirmation_box").html(data);
		openPopup("#confirmation_box");
	});
};

module.exports.submitPasswordReset = function (id) {
	var formData = $('#PromptForm').serialize();
	var url = "/users/initiatePasswordReset/" + id;
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		data: formData,
		success: function success(data, textStatus) {
			handleGenericAjaxResponse(data);
		},
		complete: function complete() {
			$(".loading").hide();
			$("#confirmation_box").fadeOut();
			$("#gray_out").fadeOut();
		},
		type: "post",
		cache: false,
		url: url
	});
};

module.exports.submitMessageForm = function (url, form, target) {
	if (!$('#PostMessage').val()) {
		showMessage("fail", "Cannot submit empty message.");
	} else {
		submitGenericForm(url, form, target);
	}
};

module.exports.submitGenericForm = function (url, form, target) {
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		data: $('#' + form).serialize(),
		success: function success(data, textStatus) {
			$('#top').html(data);
			showMessage("success", "Message added.");
		},
		complete: function complete() {
			$(".loading").hide();
		},
		type: "post",
		cache: false,
		url: url
	});
};

module.exports.acceptObject = function (type, id, event) {
	name = '#ShadowAttribute_' + id + '_accept';
	var formData = $(name).serialize();
	$.ajax({
		data: formData,
		success: function success(data, textStatus) {
			updateIndex(event, 'event');
			eventUnpublish();
			handleGenericAjaxResponse(data);
		},
		type: "post",
		cache: false,
		url: "/shadow_attributes/accept/" + id
	});
};

module.exports.eventUnpublish = function () {
	$('.publishButtons').show();
	$('.exportButtons').hide();
	$('.published').hide();
	$('.notPublished').show();
};

module.exports.updateIndex = function (id, context, newPage) {
	if (typeof newPage !== 'undefined') page = newPage;
	var url, div;
	if (context == 'event') {
		url = currentUri;
		div = "#attributes_div";
	}
	if (context == 'template') {
		url = "/template_elements/index/" + id;
		div = "#templateElements";
	}
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		dataType: "html",
		cache: false,
		success: function success(data, textStatus) {
			$(".loading").hide();
			$(div).html(data);
		},
		url: url
	});
};

module.exports.updateAttributeFieldOnSuccess = function (name, type, id, field, event) {
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			if (field != 'timestamp') {
				$(".loading").show();
			}
		},
		dataType: "html",
		cache: false,
		success: function success(data, textStatus) {
			if (field != 'timestamp') {
				$(".loading").hide();
				$(name + '_solid').html(data);
				$(name + '_placeholder').empty();
				$(name + '_solid').show();
			} else {
				$('#' + type + '_' + id + '_' + 'timestamp_solid').html(data);
			}
		},
		url: "/attributes/fetchViewValue/" + id + "/" + field
	});
};

module.exports.activateField = function (type, id, field, event) {
	resetForms();
	if (type == 'denyForm') return;
	var objectType = 'attributes';
	if (type == 'ShadowAttribute') {
		objectType = 'shadow_attributes';
	}
	var name = '#' + type + '_' + id + '_' + field;
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		dataType: "html",
		cache: false,
		success: function success(data, textStatus) {
			$(".loading").hide();
			$(name + '_placeholder').html(data);
			postActivationScripts(name, type, id, field, event);
		},
		url: "/" + objectType + "/fetchEditForm/" + id + "/" + field
	});
};

module.exports.submitQuickTag = function (form) {
	$('#' + form).submit();
};

//if someone clicks an inactive field, replace it with the hidden form field. Also, focus it and bind a focusout event, so that it gets saved if the user clicks away.
//If a user presses enter, submit the form
module.exports.postActivationScripts = function (name, type, id, field, event) {
	$(name + '_field').focus();
	inputFieldButtonActive(name + '_field');
	if (field == 'value' || field == 'comment') {
		autoresize($(name + '_field')[0]);
		$(name + '_field').on('keyup', function () {
			autoresize(this);
		});
	}
	$(name + '_form').submit(function (e) {
		e.preventDefault();
		submitForm(type, id, field, event);
		return false;
	});

	$(name + '_form').bind("focusout", function () {
		inputFieldButtonPassive(name + '_field');
	});

	$(name + '_form').bind("focusin", function () {
		inputFieldButtonActive(name + '_field');
	});

	$(name + '_form').bind("keydown", function (e) {
		if (e.ctrlKey && (e.keyCode == 13 || e.keyCode == 10)) {
			submitForm(type, id, field, event);
		}
	});
	$(name + '_field').closest('.inline-input-container').children('.inline-input-accept').bind('click', function () {
		submitForm(type, id, field, event);
	});

	$(name + '_field').closest('.inline-input-container').children('.inline-input-decline').bind('click', function () {
		resetForms();
	});

	$(name + '_solid').hide();
};

module.exports.addSighting = function (type, attribute_id, event_id, page) {
	$('#Sighting_' + attribute_id + '_type').val(type);
	$.ajax({
		data: $('#Sighting_' + attribute_id).closest("form").serialize(),
		cache: false,
		success: function success(data, textStatus) {
			handleGenericAjaxResponse(data);
			var result = JSON.parse(data);
			if (result.saved == true) {
				$('.sightingsCounter').each(function (counter) {
					$(this).html(parseInt($(this).html()) + 1);
				});
				updateIndex(event_id, 'event');
			}
		},
		error: function error() {
			showMessage('fail', 'Request failed for an unknown reason.');
			updateIndex(context, 'event');
		},
		type: "post",
		url: "/sightings/add/" + attribute_id
	});
};

module.exports.resetForms = function () {
	$('.inline-field-solid').show();
	$('.inline-field-placeholder').empty();
};

module.exports.inputFieldButtonActive = function (selector) {
	$(selector).closest('.inline-input-container').children('.inline-input-accept').removeClass('inline-input-passive').addClass('inline-input-active');
	$(selector).closest('.inline-input-container').children('.inline-input-decline').removeClass('inline-input-passive').addClass('inline-input-active');
};

module.exports.inputFieldButtonPassive = function (selector) {
	$(selector).closest('.inline-input-container').children('.inline-input-accept').addClass('inline-input-passive').removeClass('inline-input-active');
	$(selector).closest('.inline-input-container').children('.inline-input-daecline').addClass('inline-input-passive').removeClass('inline-input-active');
};

module.exports.autoresize = function (textarea) {
	textarea.style.height = '20px';
	textarea.style.height = textarea.scrollHeight + 'px';
};

// submit the form - this can be triggered by unfocusing the activated form field or by submitting the form (hitting enter)
// after the form is submitted, intercept the response and act on it
module.exports.submitForm = function (type, id, field, context) {
	var object_type = 'attributes';
	var action = "editField";
	var name = '#' + type + '_' + id + '_' + field;
	if (type == 'ShadowAttribute') {
		object_type = 'shadow_attributes';
	}
	$.ajax({
		data: $(name + '_field').closest("form").serialize(),
		cache: false,
		success: function success(data, textStatus) {
			handleAjaxEditResponse(data, name, type, id, field, context);
		},
		error: function error() {
			showMessage('fail', 'Request failed for an unknown reason.');
			updateIndex(context, 'event');
		},
		type: "post",
		url: "/" + object_type + "/" + action + "/" + id
	});
	$(name + '_field').unbind("keyup");
	$(name + '_form').unbind("focusout");
	return false;
};

module.exports.quickSubmitTagForm = function (event_id, tag_id) {
	$('#EventTag').val(tag_id);
	$.ajax({
		data: $('#EventSelectTagForm').closest("form").serialize(),
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data, textStatus) {
			loadEventTags(event_id);
			handleGenericAjaxResponse(data);
		},
		error: function error() {
			showMessage('fail', 'Could not add tag.');
			loadEventTags(event_id);
		},
		complete: function complete() {
			$("#popover_form").fadeOut();
			$("#gray_out").fadeOut();
			$(".loading").hide();
		},
		type: "post",
		url: "/events/addTag/" + event_id
	});
	return false;
};

module.exports.quickSubmitAttributeTagForm = function (attribute_id, tag_id) {
	$('#AttributeTag').val(tag_id);
	if (attribute_id == 'selected') {
		$('#AttributeAttributeIds').val(getSelected());
	}
	$.ajax({
		data: $('#AttributeSelectTagForm').closest("form").serialize(),
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data, textStatus) {
			if (attribute_id == 'selected') {
				updateIndex(0, 'event');
			} else {
				loadAttributeTags(attribute_id);
			}
			handleGenericAjaxResponse(data);
		},
		error: function error() {
			showMessage('fail', 'Could not add tag.');
			loadAttributeTags(attribute_id);
		},
		complete: function complete() {
			$("#popover_form").fadeOut();
			$("#gray_out").fadeOut();
			$(".loading").hide();
		},
		type: "post",
		url: "/attributes/addTag/" + attribute_id
	});
	return false;
};

module.exports.handleAjaxEditResponse = function (data, name, type, id, field, event) {
	var responseArray = JSON.parse(data);
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
	if (responseArray.hasOwnProperty('check_publish')) {
		checkAndSetPublishedInfo();
	}
};

module.exports.handleGenericAjaxResponse = function (data) {
	if (typeof data == 'string') {
		var responseArray = JSON.parse(data);
	} else {
		var responseArray = data;
	}
	if (responseArray.saved) {
		showMessage('success', responseArray.success);
		if (responseArray.hasOwnProperty('check_publish')) {
			checkAndSetPublishedInfo();
		}
		return true;
	} else {
		showMessage('fail', responseArray.errors);
		return false;
	}
};

module.exports.toggleAllAttributeCheckboxes = function () {
	if ($(".select_all").is(":checked")) {
		$(".select_attribute").prop("checked", true);
		$(".select_proposal").prop("checked", true);
	} else {
		$(".select_attribute").prop("checked", false);
		$(".select_proposal").prop("checked", false);
	}
};

module.exports.toggleAllTaxonomyCheckboxes = function () {
	if ($(".select_all").is(":checked")) {
		$(".select_taxonomy").prop("checked", true);
	} else {
		$(".select_taxonomy").prop("checked", false);
	}
};

module.exports.attributeListAnyAttributeCheckBoxesChecked = function () {
	if ($('.select_attribute:checked').length > 0) $('.mass-select').removeClass('hidden');else $('.mass-select').addClass('hidden');
};

module.exports.attributeListAnyProposalCheckBoxesChecked = function () {
	if ($('.select_proposal:checked').length > 0) $('.mass-proposal-select').removeClass('hidden');else $('.mass-proposal-select').addClass('hidden');
};

module.exports.taxonomyListAnyCheckBoxesChecked = function () {
	if ($('.select_taxonomy:checked').length > 0) $('.mass-select').show();else $('.mass-select').hide();
};

module.exports.multiSelectAction = function (event, context) {
	var settings = {
		deleteAttributes: {
			confirmation: "Are you sure you want to delete all selected attributes?",
			controller: "attributes",
			camelCase: "Attribute",
			alias: "attribute",
			action: "delete"
		},
		acceptProposals: {
			confirmation: "Are you sure you want to accept all selected proposals?",
			controller: "shadow_attributes",
			camelCase: "ShadowAttribute",
			alias: "proposal",
			action: "accept"
		},
		discardProposals: {
			confirmation: "Are you sure you want to discard all selected proposals?",
			controller: "shadow_attributes",
			camelCase: "ShadowAttribute",
			alias: "proposal",
			action: "discard"
		}
	};
	var answer = confirm("Are you sure you want to " + settings[context]["action"] + " all selected " + settings[context]["alias"] + "s?");
	if (answer) {
		var selected = [];
		$(".select_" + settings[context]["alias"]).each(function () {
			if ($(this).is(":checked")) {
				var temp = $(this).data("id");
				selected.push(temp);
			}
		});
		$('#' + settings[context]["camelCase"] + 'Ids' + settings[context]["action"].ucfirst()).attr('value', JSON.stringify(selected));
		var formData = $('#' + settings[context]["action"] + '_selected').serialize();
		$.ajax({
			data: formData,
			cache: false,
			type: "POST",
			url: "/" + settings[context]["controller"] + "/" + settings[context]["action"] + "Selected/" + event,
			success: function success(data, textStatus) {
				updateIndex(event, 'event');
				var result = handleGenericAjaxResponse(data);
				if (settings[context]["action"] != "discard" && result == true) eventUnpublish();
			}
		});
	}
	return false;
};

module.exports.editSelectedAttributes = function (event) {
	simplePopup("/attributes/editSelected/" + event);
};

module.exports.addSelectedTaxonomies = function (taxonomy) {
	$.get("/taxonomies/taxonomyMassConfirmation/" + taxonomy, function (data) {
		$("#confirmation_box").html(data);
		openPopup("#confirmation_box");
	});
};

module.exports.submitMassTaxonomyTag = function () {
	$('#PromptForm').submit();
};

module.exports.getSelected = function () {
	var selected = [];
	$(".select_attribute").each(function () {
		if ($(this).is(":checked")) {
			var test = $(this).data("id");
			selected.push(test);
		}
	});
	return JSON.stringify(selected);
};

module.exports.getSelectedTaxonomyNames = function () {
	var selected = [];
	$(".select_taxonomy").each(function () {
		if ($(this).is(":checked")) {
			var row = $(this).data("id");
			var temp = $('#tag_' + row).html();
			temp = $("<div/>").html(temp).text();
			selected.push(temp);
		}
	});
	$('#TaxonomyNameList').val(JSON.stringify(selected));
};

module.exports.loadEventTags = function (id) {
	$.ajax({
		dataType: "html",
		cache: false,
		success: function success(data, textStatus) {
			$(".eventTagContainer").html(data);
		},
		url: "/tags/showEventTag/" + id
	});
};

module.exports.removeEventTag = function (event, tag) {
	var answer = confirm("Are you sure you want to remove this tag from the event?");
	if (answer) {
		var formData = $('#removeTag_' + tag).serialize();
		$.ajax({
			beforeSend: function beforeSend(XMLHttpRequest) {
				$(".loading").show();
			},
			data: formData,
			type: "POST",
			cache: false,
			url: "/events/removeTag/" + event + '/' + tag,
			success: function success(data, textStatus) {
				loadEventTags(event);
				handleGenericAjaxResponse(data);
			},
			complete: function complete() {
				$(".loading").hide();
			}
		});
	}
	return false;
};

module.exports.loadAttributeTags = function (id) {
	$.ajax({
		dataType: "html",
		cache: false,
		success: function success(data, textStatus) {
			$("#Attribute_" + id + "_tr .attributeTagContainer").html(data);
		},
		url: "/tags/showAttributeTag/" + id
	});
};

module.exports.removeObjectTagPopup = function (context, object, tag) {
	$.get("/" + context + "s/removeTag/" + object + '/' + tag, function (data) {
		$("#confirmation_box").html(data);
		openPopup("#confirmation_box");
	});
};

module.exports.removeObjectTag = function (context, object, tag) {
	var formData = $('#PromptForm').serialize();
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		data: formData,
		type: "POST",
		cache: false,
		url: "/" + context.toLowerCase() + "s/removeTag/" + object + '/' + tag,
		success: function success(data, textStatus) {
			$("#confirmation_box").fadeOut();
			$("#gray_out").fadeOut();
			if (context == 'Attribute') {
				loadAttributeTags(object);
			} else {
				loadEventTags(object);
			}
			handleGenericAjaxResponse(data);
		},
		complete: function complete() {
			$(".loading").hide();
		}
	});
	return false;
};

module.exports.clickCreateButton = function (event, type) {
	var destination = 'attributes';
	if (type == 'Proposal') destination = 'shadow_attributes';
	simplePopup("/" + destination + "/add/" + event);
};

module.exports.submitPopoverForm = function (context_id, referer, update_context_id) {
	var url = null;
	var context = 'event';
	var contextNamingConvention = 'Attribute';
	var closePopover = true;
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
		case 'addSighting':
			url = "/sightings/add/" + context_id;
			closePopover = false;
			break;
	}
	if (url !== null) {
		$.ajax({
			beforeSend: function beforeSend(XMLHttpRequest) {
				$(".loading").show();
				if (closePopover) {
					$("#gray_out").fadeOut();
					$("#popover_form").fadeOut();
				}
			},
			data: $("#submitButton").closest("form").serialize(),
			success: function success(data, textStatus) {
				if (closePopover) {
					var result = handleAjaxPopoverResponse(data, context_id, url, referer, context, contextNamingConvention);
				}
				if (referer == 'addSighting') {
					updateIndex(update_context_id, 'event');
					$.get("/sightings/listSightings/" + id + "/attribute", function (data) {
						$("#sightingsData").html(data);
					});
					$('.sightingsToggle').removeClass('btn-primary');
					$('.sightingsToggle').addClass('btn-inverse');
					$('#sightingsListAllToggle').removeClass('btn-inverse');
					$('#sightingsListAllToggle').addClass('btn-primary');
				}
				if (context == 'event' && (referer == 'add' || referer == 'massEdit' || referer == 'replaceAttributes')) eventUnpublish();
				$(".loading").hide();
			},
			type: "post",
			url: url
		});
	}
};

module.exports.handleAjaxPopoverResponse = function (response, context_id, url, referer, context, contextNamingConvention) {
	var responseArray = JSON.parse(response);
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
			async: true,
			dataType: "html",
			success: function success(data, textStatus) {
				$("#popover_form").html(data);
				openPopup("#popover_form");
				var error_context = context.charAt(0).toUpperCase() + context.slice(1);
				handleValidationErrors(responseArray.errors, context, contextNamingConvention);
				if (!isEmpty(responseArray)) {
					$("#formWarning").show();
					$("#formWarning").html('The object(s) could not be saved. Please, try again.');
				}
				recoverValuesFromPersistance(savedArray);
				$(".loading").hide();
			},
			url: url
		});
	}
};

module.exports.isEmpty = function (obj) {
	var name;
	for (name in obj) {
		return false;
	}
	return true;
};

//before we update the form (in case the action failed), we want to retrieve the data from every field, so that we can set the fields in the new form that we fetch
module.exports.saveValuesForPersistance = function () {
	return fieldsArray.map(function (i) {
		return $("#" + i).val();
	});
};

module.exports.recoverValuesFromPersistance = function (formPersistanceArray) {
	formPersistanceArray.map(function (val, ind) {
		$("#" + fieldsArray[ind]).val(val);
	});
};

module.exports.handleValidationErrors = function (responseArray, context, contextNamingConvention) {
	for (var k in responseArray) {
		var elementName = k.charAt(0).toUpperCase() + k.slice(1);
		$("#" + contextNamingConvention + elementName).parent().addClass("error");
		$("#" + contextNamingConvention + elementName).parent().append("<div class=\"error-message\">" + responseArray[k] + "</div>");
	}
};

module.exports.toggleHistogramType = function (type, old) {
	var done = false;
	old.forEach(function (entry) {
		if (type == entry) {
			done = true;
			old.splice(old.indexOf(entry), 1);
		}
	});
	if (done == false) old.push(type);
	updateHistogram(JSON.stringify(old));
};

module.exports.updateHistogram = function (selected) {
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		dataType: "html",
		cache: false,
		success: function success(data, textStatus) {
			$(".loading").hide();
			$("#histogram").html(data);
		},
		url: "/users/histogram/" + selected
	});
};

module.exports.showMessage = function (success, message, context) {
	if (typeof context !== "undefined") {
		$("#ajax_" + success, window.parent.document).html(message);
		var duration = 1000 + message.length * 40;
		$("#ajax_" + success + "_container", window.parent.document).fadeIn("slow");
		$("#ajax_" + success + "_container", window.parent.document).delay(duration).fadeOut("slow");
	}
	$("#ajax_" + success).html(message);
	var duration = 1000 + message.length * 40;
	$("#ajax_" + success + "_container").fadeIn("slow");
	$("#ajax_" + success + "_container").delay(duration).fadeOut("slow");
};

module.exports.cancelPopoverForm = function () {
	$("#gray_out").fadeOut();
	$("#popover_form").fadeOut();
	$("#screenshot_box").fadeOut();
	$("#confirmation_box").fadeOut();
	$('#gray_out').fadeOut();
	$('#popover_form').fadeOut();
};

module.exports.activateTagField = function () {
	$("#addTagButton").hide();
	$("#addTagField").show();
};

module.exports.tagFieldChange = function () {
	if ($("#addTagField :selected").val() > 0) {
		var selected_id = $("#addTagField :selected").val();
		var selected_text = $("#addTagField :selected").text();
		if ($.inArray(selected_id, selectedTags) == -1) {
			selectedTags.push(selected_id);
			appendTemplateTag(selected_id);
		}
	}
	$("#addTagButton").show();
	$("#addTagField").hide();
};

module.exports.appendTemplateTag = function (selected_id) {
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		dataType: "html",
		cache: false,
		success: function success(data, textStatus) {
			$(".loading").hide();
			$("#tags").append(data);
		},
		url: "/tags/viewTag/" + selected_id
	});
	updateSelectedTags();
};

module.exports.addAllTags = function (tagArray) {
	parsedTagArray = JSON.parse(tagArray);
	parsedTagArray.forEach(function (tag) {
		appendTemplateTag(tag);
	});
};

module.exports.removeTemplateTag = function (id, name) {
	selectedTags.forEach(function (tag) {
		if (tag == id) {
			var index = selectedTags.indexOf(id);
			if (index > -1) {
				selectedTags.splice(index, 1);
				updateSelectedTags();
			}
		}
	});
	$('#tag_bubble_' + id).remove();
};

module.exports.updateSelectedTags = function () {
	$('#hiddenTags').attr("value", JSON.stringify(selectedTags));
};

module.exports.saveElementSorting = function (order) {
	var _$$ajax;

	$.ajax((_$$ajax = {
		data: order,
		dataType: "json",
		contentType: "application/json",
		cache: false,
		success: function success(data, textStatus) {
			handleGenericAjaxResponse(data);
		},
		type: "post"
	}, _defineProperty(_$$ajax, 'cache', false), _defineProperty(_$$ajax, 'url', "/templates/saveElementSorting/"), _$$ajax));
};

module.exports.templateAddElementClicked = function (id) {
	simplePopup("/template_elements/templateElementAddChoices/" + id);
};

module.exports.templateAddElement = function (type, id) {
	simplePopup("/template_elements/add/" + type + "/" + id);
};

module.exports.templateUpdateAvailableTypes = function () {
	$("#innerTypes").empty();
	var type = $("#TemplateElementAttributeType option:selected").text();
	var complex = $('#TemplateElementAttributeComplex:checked').val();
	if (complex && type != 'Select Type') {
		currentTypes.forEach(function (entry) {
			$("#innerTypes").append("<div class=\"templateTypeBox\" id=\"" + entry + "TypeBox\">" + entry + "</div>");
		});
		$('#outerTypes').show();
	} else $('#outerTypes').hide();
};

module.exports.populateTemplateTypeDropdown = function () {
	var cat = $("#TemplateElementAttributeCategory option:selected").text();
	currentTypes = [];
	if (cat == 'Select Category') {
		$('#TemplateElementAttributeType').html("<option>Select Type</option>");
	} else {
		var complex = $('#TemplateElementAttributeComplex:checked').val();
		if (cat in typeGroupCategoryMapping) {
			$('#TemplateElementAttributeType').html("<option>Select Type</option>");
			typeGroupCategoryMapping[cat].forEach(function (entry) {
				$('#TemplateElementAttributeType').append("<option>" + entry + "</option>");
			});
		} else {
			complex = false;
		}
		if (!complex) {
			$('#TemplateElementAttributeType').html("<option>Select Type</option>");
			categoryTypes[cat].forEach(function (entry) {
				$('#TemplateElementAttributeType').append("<option>" + entry + "</option>");
			});
		}
	}
};

module.exports.templateElementAttributeTypeChange = function () {
	var complex = $('#TemplateElementAttributeComplex:checked').val();
	var type = $("#TemplateElementAttributeType option:selected").text();
	currentTypes = [];
	if (type != 'Select Type') {
		if (complex) {
			complexTypes[type]["types"].forEach(function (entry) {
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
};

module.exports.templateElementAttributeCategoryChange = function (category) {
	if (category in typeGroupCategoryMapping) {
		$('#complexToggle').show();
	} else {
		$('#complexToggle').hide();
	}
	if (category != 'Select Type') {
		populateTemplateTypeDropdown();
	}
	templateUpdateAvailableTypes();
};

module.exports.templateElementFileCategoryChange = function (category) {
	if (category == '') {
		$("#TemplateElementFileMalware")[0].disabled = true;
		$("#TemplateElementFileMalware")[0].checked = false;
	} else {
		if (categoryArray[category].length == 2) {
			$("#TemplateElementFileMalware")[0].disabled = false;
			$("#TemplateElementFileMalware")[0].checked = true;
		} else {
			$("#TemplateElementFileMalware")[0].disabled = true;
			if (categoryArray[category] == 'attachment') $("#TemplateElementFileMalware")[0].checked = false;else $("#TemplateElementFileMalware")[0].checked = true;
		}
	}
};

module.exports.openPopup = function (id) {
	var window_height = $(window).height();
	var popup_height = $(id).height();
	if (window_height < popup_height) {
		$(id).css("top", 0);
		$(id).css("height", window_height);
		$(id).addClass('vertical-scroll');
	} else {
		if (window_height > 300 + popup_height) {
			var top_offset = (window_height - popup_height) / 2 - 150;
		} else {
			var top_offset = (window_height - popup_height) / 2;
		}
		$(id).css("top", top_offset + 'px');
	}
	$("#gray_out").fadeIn();
	$(id).fadeIn();
};

module.exports.getPopup = function (id, context, target, admin, popupType) {
	$("#gray_out").fadeIn();
	var url = "";
	if (typeof admin !== 'undefined' && admin != '') url += "/admin";
	if (context != '') url += "/" + context;
	if (target != '') url += "/" + target;
	if (id != '') url += "/" + id;
	if (popupType == '' || typeof popupType == 'undefined') popupType = '#popover_form';
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		dataType: "html",
		async: true,
		cache: false,
		success: function success(data, textStatus) {
			$(".loading").hide();
			$(popupType).html(data);
			openPopup(popupType);
		},
		url: url
	});
};

module.exports.simplePopup = function (url) {
	$("#gray_out").fadeIn();
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		dataType: "html",
		async: true,
		cache: false,
		success: function success(data, textStatus) {
			$(".loading").hide();
			$("#popover_form").html(data);
			openPopup("#popover_form");
		},
		url: url
	});
};

module.exports.resizePopoverBody = function () {
	var bodyheight = $(window).height();
	bodyheight = 3 * bodyheight / 4 - 150;
	$("#popover_choice_main").css({ "max-height": bodyheight });
};

module.exports.populateTemplateHiddenFileDiv = function (files) {
	$('#TemplateFileArray').val(JSON.stringify(files));
};

module.exports.populateTemplateFileBubbles = function () {
	var fileObjectArray = JSON.parse($('#TemplateFileArray').val());
	fileObjectArray.forEach(function (entry) {
		templateAddFileBubble(entry.element_id, false, entry.filename, entry.tmp_name, 'yes');
	});
};

module.exports.templateFileHiddenAdd = function (files, element_id, batch) {
	var fileArray = $.parseJSON($('#TemplateFileArray', window.parent.document).val());
	var contained = false;
	for (var j = 0; j < files.length; j++) {
		for (var i = 0; i < fileArray.length; i++) {
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
};

module.exports.htmlEncode = function (value) {
	return $('<div/>').text(value).html();
};

module.exports.templateAddFileBubble = function (element_id, iframe, filename, tmp_name, batch) {
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
};

module.exports.templateDeleteFileBubble = function (filename, tmp_name, element_id, context, batch) {
	$(".loading").show();
	$.ajax({
		type: "post",
		cache: false,
		url: "/templates/deleteTemporaryFile/" + tmp_name
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
	oldArray.forEach(function (entry) {
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
};

module.exports.templateFileUploadTriggerBrowse = function (id) {
	$('#upload_' + id + '_file').click();
};

module.exports.freetextRemoveRow = function (id, event_id) {
	$('#row_' + id).hide();
	$('#Attribute' + id + 'Save').attr("value", "0");
	if ($(".freetext_row:visible").length == 0) {
		window.location = "/events/" + event_id;
	}
};

module.exports.indexEvaluateFiltering = function () {
	if (filterContext == "event") {
		if (filtering.published != 2) {
			$('#value_published').html(publishedOptions[filtering.published]);
		} else {
			$('#value_published').html("");
		}
		if (filtering.hasproposal != 2) {
			$('#value_hasproposal').html(publishedOptions[filtering.hasproposal]);
		} else {
			$('#value_hasproposal').html("");
		}
		if (filtering.date.from != null || filtering.date.from != null) {
			var text = "";
			if (filtering.date.from != "") text = "From: " + $('<span>').text(filtering.date.from).html();
			if (filtering.date.until != "") {
				if (text != "") text += " ";
				text += "Until: " + $('<span>').text(filtering.date.until).html();
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
				if (filtering[differentFilters[i]] == 1) text = "Yes";else if (filtering[differentFilters[i]] == 0) text = "No";
				$('#value_' + differentFilters[i]).text(text);
			} else {
				$('#value_' + differentFilters[i]).text("");
			}
		}
		for (var i = 0; i < simpleFilters.length; i++) {
			indexEvaluateSimpleFiltering(simpleFilters[i]);
		}
	}
	indexSetTableVisibility();
	indexSetRowVisibility();
	$('#generatedURLContent').text(indexCreateFilters());
};

module.exports.quickFilter = function (passedArgs, url) {
	passedArgs["searchall"] = $('#quickFilterField').val().trim();
	for (var key in passedArgs) {
		url += "/" + key + ":" + passedArgs[key];
	}
	window.location.href = url;
};

module.exports.executeFilter = function (passedArgs, url) {
	for (var key in passedArgs) {
		url += "/" + key + ":" + passedArgs[key];
	}window.location.href = url;
};

module.exports.quickFilterTaxonomy = function (taxonomy_id, passedArgs) {
	var url = "/taxonomies/view/" + taxonomy_id + "/filter:" + $('#quickFilterField').val();
	window.location.href = url;
};

module.exports.quickFilterRemoteEvents = function (passedArgs, id) {
	passedArgs["searchall"] = $('#quickFilterField').val();
	var url = "/servers/previewIndex/" + id;
	for (var key in passedArgs) {
		url += "/" + key + ":" + passedArgs[key];
	}
	window.location.href = url;
};

$('#quickFilterField').bind("enterKey", function (e) {
	$('#quickFilterButton').trigger("click");
});
$('#quickFilterField').keyup(function (e) {
	if (e.keyCode == 13) {
		$('#quickFilterButton').trigger("click");
	}
});

module.exports.remoteIndexApplyFilters = function () {
	var url = actionUrl + '/' + $("#EventFilter").val();
	window.location.href = url;
};

module.exports.indexApplyFilters = function () {
	var url = indexCreateFilters();
	window.location.href = url;
};

module.exports.indexCreateFilters = function () {
	text = "";
	if (filterContext == 'event') {
		if (filtering.published != "2") {
			text += "searchpublished:" + filtering.published;
		}
		if (filtering.hasproposal != "2") {
			if (text != "") text += "/";
			text += "searchhasproposal:" + filtering.hasproposal;
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
};

module.exports.indexBuildArray = function (type, text) {
	temp = "";
	if (text != "") temp += "/";
	temp += "search" + type + ":";
	if (filtering[type].NOT.length == 0 && filtering[type].OR.length == 0) return text;
	var swap = filtering[type].OR.length;
	var temp_array = filtering[type].OR.concat(filtering[type].NOT);
	for (var i = 0; i < temp_array.length; i++) {
		if (i > 0) temp += "|";
		if (i >= swap) temp += "!";
		temp += temp_array[i];
	}
	text += temp;
	return text;
};

module.exports.indexSetRowVisibility = function () {
	for (var i = 0; i < allFields.length; i++) {
		if ($("#value_" + allFields[i]).text().trim() != "") {
			$("#row_" + allFields[i]).show();
		} else {
			$("#row_" + allFields[i]).hide();
		}
	}
};

module.exports.indexEvaluateSimpleFiltering = function (field) {
	text = "";
	if (filtering[field].OR.length == 0 && filtering[field].NOT.length == 0) {
		$('#value_' + field).html(text);
		return false;
	}
	if (filtering[field].OR.length != 0) {
		for (var i = 0; i < filtering[field].OR.length; i++) {
			if (i > 0) text += '<span class="green bold"> OR </span>';
			if (typedFields.indexOf(field) == -1) {
				text += $('<span>').text(filtering[field].OR[i]).html();
			} else {
				for (var j = 0; j < typeArray[field].length; j++) {
					if (typeArray[field][j].id == filtering[field].OR[i]) {
						text += $('<span>').text(typeArray[field][j].value).html();
					}
				}
			}
		}
	}
	if (filtering[field].NOT.length != 0) {
		for (var i = 0; i < filtering[field].NOT.length; i++) {
			if (i == 0) {
				if (text != "") text += '<span class="red bold"> AND NOT </span>';else text += '<span class="red bold">NOT </span>';
			} else text += '<span class="red bold"> AND NOT </span>';
			if (typedFields.indexOf(field) == -1) {
				text += $('<span>').text(filtering[field].NOT[i]).html();
			} else {
				for (var j = 0; j < typeArray[field].length; j++) {
					if (typeArray[field][j].id == filtering[field].NOT[i]) {
						text += $('<span>').text(typeArray[field][j].value).html();
					}
				}
			}
		}
	}
	$('#value_' + field).html(text);
};

module.exports.indexAddRule = function (param) {
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
		} else if (param.data.param1 == "hasproposal") {
			var value = escape($('#EventSearchhasproposal').val());
			if (value != "") filtering.hasproposal = value;
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
};

module.exports.indexSetTableVisibility = function () {
	var visible = false;
	if ($("[id^='value_']").text().trim() != "" && $("[id^='value_']").text().trim() != "-1") {
		visible = true;
	}
	if (visible == true) $('#FilterplaceholderTable').hide();else $('#FilterplaceholderTable').show();
};

module.exports.indexRuleChange = function () {
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
	$('#addRuleButton').click({ param1: rule }, indexAddRule);
};

module.exports.indexFilterClearRow = function (field) {
	$('#value_' + field).html("");
	$('#row_' + field).hide();
	if (field == "date") {
		filtering.date.from = "";
		filtering.date.until = "";
	} else if (field == "published") {
		filtering.published = 2;
	} else if (field == "hasproposal") {
		filtering.hasproposal = 2;
	} else if (differentFilters.indexOf(field) != -1) {
		filtering[field] = "";
	} else {
		filtering[field].NOT = [];
		filtering[field].OR = [];
	}
	indexSetTableVisibility();
	indexEvaluateFiltering();
};

module.exports.restrictEventViewPagination = function () {
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
		start = page - 5;
		end = page + 5;
	}

	if (start > 2) {
		$("#apage" + start).parent().before("<li><a href id='aExpandLeft'>...</a></li>");
		$("#aExpandLeft").click(function () {
			expandPagination(0, 0);return false;
		});
		$("#bpage" + start).parent().before("<li><a href id='bExpandLeft'>...</a></li>");
		$("#bExpandLeft").click(function () {
			expandPagination(1, 0);return false;
		});
	}

	if (end < count - 1) {
		$("#apage" + end).parent().after("<li><a href id='aExpandRight'>...</a></li>");
		$("#aExpandRight").click(function () {
			expandPagination(0, 1);return false;
		});
		$("#bpage" + end).parent().after("<li><a href id='bExpandRight'>...</a></li>");
		$("#bExpandRight").click(function () {
			expandPagination(1, 1);return false;
		});
	}

	for (i = 1; i < count + 1; i++) {
		if (i != 1 && i != count && (i < start || i > end)) {
			$("#apage" + i).hide();
			$("#bpage" + i).hide();
		}
	}
};

module.exports.expandPagination = function (bottom, right) {
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
};

module.exports.getSubGroupFromSetting = function (setting) {
	var temp = setting.split('.');
	if (temp[0] == "Plugin") {
		temp = temp[1];
		if (temp.indexOf('_') > -1) {
			temp = temp.split('_');
			return temp[0];
		}
	}
	return 'general';
};

module.exports.serverSettingsActivateField = function (setting, id) {
	resetForms();
	$('.inline-field-placeholder').hide();
	var fieldName = "#setting_" + getSubGroupFromSetting(setting) + "_" + id;
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		dataType: "html",
		cache: false,
		success: function success(data, textStatus) {
			$(".loading").hide();
			$(fieldName + "_placeholder").html(data);
			$(fieldName + "_solid").hide();
			$(fieldName + "_placeholder").show();
			serverSettingsPostActivationScripts(fieldName, setting, id);
		},
		url: "/servers/serverSettingsEdit/" + setting + "/" + id
	});
};

module.exports.serverSettingsPostActivationScripts = function (name, setting, id) {
	$(name + '_field').focus();
	inputFieldButtonActive(name + '_field');

	$(name + '_form').submit(function (e) {
		e.preventDefault();
		serverSettingSubmitForm(name, setting, id);
		return false;
	});

	$(name + '_form').bind("focusout", function () {
		inputFieldButtonPassive(name + '_field');
	});

	$(name + '_form').bind("focusin", function () {
		inputFieldButtonActive(name + '_field');
	});

	$(name + '_form').bind("keydown", function (e) {
		if (e.ctrlKey && (e.keyCode == 13 || e.keyCode == 10)) {
			serverSettingSubmitForm(name, setting, id);
		}
	});
	$(name + '_field').closest('.inline-input-container').children('.inline-input-accept').bind('click', function () {
		serverSettingSubmitForm(name, setting, id);
	});
	$(name + '_field').closest('.inline-input-container').children('.inline-input-decline').bind('click', function () {
		resetForms();
		$('.inline-field-placeholder').hide();
	});

	$(name + '_solid').hide();
};

module.exports.serverSettingSubmitForm = function (name, setting, id) {
	var subGroup = getSubGroupFromSetting(setting);
	var formData = $(name + '_field').closest("form").serialize();
	$.ajax({
		data: formData,
		cache: false,
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data, textStatus) {
			$.ajax({
				type: "get",
				url: "/servers/serverSettingsReloadSetting/" + setting + "/" + id,
				success: function success(data2, textStatus2) {
					$('#' + subGroup + "_" + id + '_row').replaceWith(data2);
					$(".loading").hide();
				},
				error: function error() {
					showMessage('fail', 'Could not refresh the table.');
				}
			});
		},
		error: function error() {
			showMessage('fail', 'Request failed for an unknown reason.');
			resetForms();
			$('.inline-field-placeholder').hide();
		},
		type: "post",
		url: "/servers/serverSettingsEdit/" + setting + "/" + id + "/" + 1
	});
	$(name + '_field').unbind("keyup");
	$(name + '_form').unbind("focusout");
	return false;
};

module.exports.updateOrgCreateImageField = function (string) {
	string = escape(string);
	$.ajax({
		url: '/img/orgs/' + string + '.png',
		type: 'HEAD',
		error: function error() {
			$('#logoDiv').html('No image uploaded for this identifier');
		},
		success: function success() {
			$('#logoDiv').html('<img src="/img/orgs/' + string + '.png" style="width:24px;height:24px;"></img>');
		}
	});
};

module.exports.generateOrgUUID = function () {
	$.ajax({
		url: '/admin/organisations/generateuuid.json',
		success: function success(data) {
			$('#OrganisationUuid').val(data.uuid);
		}
	});
};

module.exports.sharingGroupIndexMembersCollapse = function (id) {
	$('#' + id + '_down').show();
	$('#' + id + '_up').hide();
};

module.exports.sharingGroupIndexMembersExpand = function (id) {
	$('#' + id + '_down').hide();
	$('#' + id + '_up').show();
};

module.exports.popoverStartup = function () {
	$('[data-toggle="popover"]').popover({
		animation: true,
		html: true
	}).click(function (e) {
		$(e.target).popover('show');
		$('[data-toggle="popover"]').not(e.target).popover('hide');
	});
	$(document).click(function (e) {
		if (!$('[data-toggle="popover"]').is(e.target)) {
			$('[data-toggle="popover"]').popover('hide');
		}
	});
};

module.exports.changeFreetextImportFrom = function () {
	$('#changeTo').find('option').remove();
	options[$('#changeFrom').val()].forEach(function (element) {
		$('#changeTo').append('<option value="' + element + '">' + element + '</option>');
	});
};

module.exports.changeFreetextImportCommentExecute = function () {
	$('.freetextCommentField').val($('#changeComments').val());
};

module.exports.changeFreetextImportExecute = function () {
	var from = $('#changeFrom').val();
	var to = $('#changeTo').val();
	$('.typeToggle').each(function () {
		if ($(this).val() == from) {
			if (selectContainsOption("#" + $(this).attr('id'), to)) $(this).val(to);
		}
	});
};

module.exports.selectContainsOption = function (selectid, value) {
	var exists = false;
	$(selectid + ' option').each(function () {
		if (this.value == value) {
			exists = true;
			return false;
		}
	});
	return exists;
};

module.exports.exportChoiceSelect = function (url, elementId, checkbox) {
	if (checkbox == 1) {
		if ($('#' + elementId + '_toggle').prop('checked')) {
			url = $('#' + elementId + '_set').html();
		}
	}
	document.location.href = url;
};

module.exports.importChoiceSelect = function (url, elementId, ajax) {
	if (ajax == 'false') {
		document.location.href = url;
	} else {
		simplePopup(url);
	}
};

module.exports.freetextImportResultsSubmit = function (id, count) {
	var attributeArray = [];
	var temp;
	for (i = 0; i < count; i++) {
		if ($('#Attribute' + i + 'Save').val() == 1) {
			temp = {
				value: $('#Attribute' + i + 'Value').val(),
				category: $('#Attribute' + i + 'Category').val(),
				type: $('#Attribute' + i + 'Type').val(),
				to_ids: $('#Attribute' + i + 'To_ids')[0].checked,
				comment: $('#Attribute' + i + 'Comment').val(),
				distribution: $('#Attribute' + i + 'Distribution').val(),
				sharing_group_id: $('#Attribute' + i + 'SharingGroupId').val(),
				data: $('#Attribute' + i + 'Data').val(),
				data_is_handled: $('#Attribute' + i + 'DataIsHandled').val()
			};
			attributeArray[attributeArray.length] = temp;
		}
	};
	$("#AttributeJsonObject").val(JSON.stringify(attributeArray));
	var formData = $(".mainForm").serialize();
	$.ajax({
		type: "post",
		cache: false,
		url: "/events/saveFreeText/" + id,
		data: formData,
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data, textStatus) {
			window.location = '/events/view/' + id;
		},
		complete: function complete() {
			$(".loading").hide();
		}
	});
};

module.exports.organisationViewContent = function (context, id) {
	organisationViewButtonHighlight(context);
	var action = "/organisations/landingpage/";
	if (context == 'members') {
		action = "/admin/users/index/searchorg:";
	}
	if (context == 'events') {
		action = "/events/index/searchorg:";
	}
	$.ajax({
		url: action + id,
		type: 'GET',
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		error: function error() {
			$('#ajaxContent').html('An error has occured, please reload the page.');
		},
		success: function success(response) {
			$('#ajaxContent').html(response);
		},
		complete: function complete() {
			$(".loading").hide();
		}
	});
};

module.exports.organisationViewButtonHighlight = function (context) {
	$(".orgViewButtonActive").hide();
	$(".orgViewButton").show();
	$("#button_" + context).hide();
	$("#button_" + context + "_active").show();
};

module.exports.simpleTabPage = function (page) {
	$(".tabMenuSides").removeClass("tabMenuActive");
	$("#page" + page + "_tab").addClass("tabMenuActive");
	$(".tabContent").hide();
	$("#page" + page + "_content").show();
	if (page == lastPage) simpleTabPageLast();
};

module.exports.simpleTabPageLast = function () {
	var summaryorgs = summaryextendorgs = remotesummaryorgs = remotesummaryextendorgs = summaryservers = "";
	var orgcounter = extendcounter = remoteorgcounter = remoteextendcounter = servercounter = 0;
	var sgname = "[Sharing group name not set!]";
	if ($('#SharingGroupName').val()) sgname = $('#SharingGroupName').val();
	var sgreleasability = "[Sharing group releasability not set!]";
	if ($('#SharingGroupReleasability').val()) sgreleasability = $('#SharingGroupReleasability').val();
	$('#summarytitle').text(sgname);
	$('#summaryreleasable').text(sgreleasability);
	organisations.forEach(function (organisation) {
		if (organisation.type == 'local') {
			if (orgcounter > 0) summaryorgs += ", ";
			summaryorgs += organisation.name;
			if (organisation.extend == true) {
				if (extendcounter > 0) summaryextendorgs += ", ";
				summaryextendorgs += organisation.name;
				extendcounter++;
			}
			orgcounter++;
		} else {
			if (remoteorgcounter > 0) remotesummaryorgs += ", ";
			remotesummaryorgs += organisation.name;
			if (organisation.extend == true) {
				if (remoteextendcounter > 0) remotesummaryextendorgs += ", ";
				remotesummaryextendorgs += organisation.name;
				remoteextendcounter++;
			}
			remoteorgcounter++;
		}
	});
	if (orgcounter == 0) $('#localText').hide();
	if (remoteorgcounter == 0) $('#externalText').hide();
	if (extendcounter == 0) summaryextendorgs = "nobody";
	if (remoteextendcounter == 0) remotesummaryextendorgs = "nobody";
	servers.forEach(function (server) {
		if (servercounter > 0) summaryservers += ", ";
		if (server.id != 0) {
			summaryservers += server.name;
			if (extendcounter == 0) summaryextendorgs = "none";
			servercounter++;
		}
		if (server.id == 0 && server.all_orgs == true) summaryorgs = "all organisations on this instance";
	});
	if ($('#SharingGroupRoaming').is(":checked")) {
		summaryservers = "any interconnected instances linked by an eligible organisation.";
	} else {
		if (servercounter == 0) {
			summaryservers = "data marked with this sharing group will not be pushed.";
		}
	}
	$('#summarylocal').text(summaryorgs);
	$('#summarylocalextend').text(summaryextendorgs);
	$('#summaryexternal').text(remotesummaryorgs);
	$('#summaryexternalextend').text(remotesummaryextendorgs);
	$('#summaryservers').text(summaryservers);
};

module.exports.sharingGroupPopulateOrganisations = function () {
	$('input[id=SharingGroupOrganisations]').val(JSON.stringify(organisations));
	$('.orgRow').remove();
	var id = 0;
	var html = '';
	organisations.forEach(function (org) {
		html = '<tr id="orgRow' + id + '" class="orgRow">';
		html += '<td class="short">' + org.type + '&nbsp;</td>';
		html += '<td>' + org.name + '&nbsp;</td>';
		html += '<td>' + org.uuid + '&nbsp;</td>';
		html += '<td class="short" style="text-align:center;">';
		if (org.removable == 1) {
			html += '<input id="orgExtend' + id + '" type="checkbox" onClick="sharingGroupExtendOrg(' + id + ')" ';
			if (org.extend) html += 'checked';
			html += '></input>';
		} else {
			html += '<span class="icon-ok"></span>';
		}
		html += '</td>';
		html += '<td class="actions short">';
		if (org.removable == 1) html += '<span class="icon-trash" onClick="sharingGroupRemoveOrganisation(' + id + ')"></span>';
		html += '&nbsp;</td></tr>';
		$('#organisations_table tr:last').after(html);
		id++;
	});
};

module.exports.sharingGroupPopulateServers = function () {
	$('input[id=SharingGroupServers]').val(JSON.stringify(servers));
	$('.serverRow').remove();
	var id = 0;
	var html = '';
	servers.forEach(function (server) {
		html = '<tr id="serverRow' + id + '" class="serverRow">';
		html += '<td>' + server.name + '&nbsp;</td>';
		html += '<td>' + server.url + '&nbsp;</td>';
		html += '<td>';
		html += '<input id="serverAddOrgs' + id + '" type="checkbox" onClick="sharingGroupServerAddOrgs(' + id + ')" ';
		if (server.all_orgs) html += 'checked';
		html += '></input>';
		html += '</td>';
		html += '<td class="actions short">';
		if (server.removable == 1) html += '<span class="icon-trash" onClick="sharingGroupRemoveServer(' + id + ')"></span>';
		html += '&nbsp;</td></tr>';
		$('#servers_table tr:last').after(html);
		id++;
	});
};

module.exports.sharingGroupExtendOrg = function (id) {
	organisations[id].extend = $('#orgExtend' + id).is(":checked");
};

module.exports.sharingGroupServerAddOrgs = function (id) {
	servers[id].all_orgs = $('#serverAddOrgs' + id).is(":checked");
};

module.exports.sharingGroupPopulateUsers = function () {
	$('input[id=SharingGroupServers]').val(JSON.stringify(organisations));
};

module.exports.sharingGroupAdd = function (context, type) {
	if (context == 'organisation') {
		var jsonids = JSON.stringify(orgids);
		url = '/organisations/fetchOrgsForSG/' + jsonids + '/' + type;
	} else if (context == 'server') {
		var jsonids = JSON.stringify(serverids);
		url = '/servers/fetchServersForSG/' + jsonids;
	}
	$("#gray_out").fadeIn();
	simplePopup(url);
};

module.exports.sharingGroupRemoveOrganisation = function (id) {
	organisations.splice(id, 1);
	orgids.splice(id, 1);
	sharingGroupPopulateOrganisations();
};

module.exports.sharingGroupRemoveServer = function (id) {
	servers.splice(id, 1);
	serverids.splice(id, 1);
	sharingGroupPopulateServers();
};

module.exports.submitPicklistValues = function (context, local) {
	if (context == 'org') {
		var localType = 'local';
		if (local == 0) localType = 'remote';
		$("#rightValues  option").each(function () {
			if (orgids.indexOf($(this).val()) == -1) {
				organisations.push({
					id: $(this).val(),
					type: localType,
					name: $(this).text(),
					extend: false,
					uuid: '',
					removable: 1
				});
			}
			orgids.push($(this).val());
			sharingGroupPopulateOrganisations();
		});
	} else if (context == 'server') {
		$("#rightValues  option").each(function () {
			if (serverids.indexOf($(this).val()) == -1) {
				servers.push({
					id: $(this).val(),
					name: $(this).text(),
					url: $(this).attr("data-url"),
					all_orgs: false,
					removable: 1
				});
			}
			serverids.push($(this).val());
			sharingGroupPopulateServers();
		});
	}
	$("#gray_out").fadeOut();
	$("#popover_form").fadeOut();
};

module.exports.cancelPicklistValues = function () {
	$("#popover_form").fadeOut();
	$("#gray_out").fadeOut();
};

module.exports.sgSubmitForm = function (action) {
	var ajax = {
		'organisations': organisations,
		'servers': servers,
		'sharingGroup': {
			'name': $('#SharingGroupName').val(),
			'releasability': $('#SharingGroupReleasability').val(),
			'description': $('#SharingGroupDescription').val(),
			'active': $('#SharingGroupActive').is(":checked"),
			'roaming': $('#SharingGroupRoaming').is(":checked")
		}
	};
	$('#SharingGroupJson').val(JSON.stringify(ajax));
	var formName = "#SharingGroup" + action + "Form";
	$(formName).submit();
};

module.exports.serverSubmitForm = function (action) {
	var ajax = {};
	switch ($('#ServerOrganisationType').val()) {
		case '0':
			ajax = {
				'id': $('#ServerLocal').val()
			};
			break;
		case '1':
			ajax = {
				'id': $('#ServerExternal').val()
			};
			break;
		case '2':
			ajax = {
				'name': $('#ServerExternalName').val(),
				'uuid': $('#ServerExternalUuid').val()
			};
			break;
	}

	$('#ServerJson').val(JSON.stringify(ajax));
	var formName = "#Server" + action + "Form";
	$(formName).submit();
};

module.exports.serverOrgTypeChange = function () {
	$(".hiddenField").hide();
	switch ($('#ServerOrganisationType').val()) {
		case '0':
			$("#ServerLocalContainer").show();
			break;
		case '1':
			$("#ServerExternalContainer").show();
			break;
		case '2':
			$("#ServerExternalUuidContainer").show();
			$("#ServerExternalNameContainer").show();
			break;
	}
};

module.exports.sharingGroupPopulateFromJson = function () {
	var jsonparsed = JSON.parse($('#SharingGroupJson').val());
	organisations = jsonparsed.organisations;
	servers = jsonparsed.servers;
	if (jsonparsed.sharingGroup.active == 1) {
		$("#SharingGroupActive").prop("checked", true);
	}
	if (jsonparsed.sharingGroup.roaming == 1) {
		$("#SharingGroupRoaming").prop("checked", true);
		$('#serverList').show();
	}
	$('#SharingGroupName').attr('value', jsonparsed.sharingGroup.name);
	$('#SharingGroupReleasability').attr('value', jsonparsed.sharingGroup.releasability);
	$('#SharingGroupDescription').text(jsonparsed.sharingGroup.description);
};

module.exports.testConnection = function (id) {
	$.ajax({
		url: '/servers/testConnection/' + id,
		type: 'GET',
		beforeSend: function beforeSend(XMLHttpRequest) {
			$("#connection_test_" + id).html('Running test...');
		},
		error: function error() {
			$("#connection_test_" + id).html('Internal error.');
		},
		success: function success(response) {
			var result = JSON.parse(response);
			switch (result.status) {
				case 1:
					status_message = "OK";
					compatibility = "Compatible";
					compatibility_colour = "green";
					colours = { 'local': 'class="green"', 'remote': 'class="green"', 'status': 'class="green"' };
					issue_colour = "red";
					if (result.mismatch == "hotfix") issue_colour = "orange";
					if (result.newer == "local") {
						colours.remote = 'class="' + issue_colour + '"';
						if (result.mismatch == "minor") {
							compatibility = "Pull only";
							compatibility_colour = "orange";
						} else if (result.mismatch == "major") {
							compatibility = "Incompatible";
							compatibility_colour = "red";
						}
					} else if (result.newer == "remote") {
						colours.local = 'class="' + issue_colour + '"';
						if (result.mismatch != "hotfix") {
							compatibility = "Incompatible";
							compatibility_colour = "red";
						}
					}
					if (result.mismatch != false) {
						if (result.newer == "remote") status_message = "Local instance outdated, update!";else status_message = "Remote outdated, notify admin!";
						colours.status = 'class="' + issue_colour + '"';
					}
					if (result.post != false) {
						var post_colour = "red";
						if (result.post == 1) {
							post_colour = "green";
							post_result = "Received sent package";
						} else if (result.post == 8) {
							post_result = "Could not POST message";
						} else if (result.post == 9) {
							post_result = "Invalid headers";
						} else if (result.post == 10) {
							post_result = "Invalid body";
						} else {
							post_colour = "orange";
							post_result = "Remote too old for this test";
						}
					}
					resultDiv = '<div>Local version: <span ' + colours.local + '>' + result.local_version + '</span><br />';
					resultDiv += '<div>Remote version: <span ' + colours.remote + '>' + result.version + '</span><br />';
					resultDiv += '<div>Status: <span ' + colours.status + '>' + status_message + '</span><br />';
					resultDiv += '<div>Compatiblity: <span class="' + compatibility_colour + '">' + compatibility + '</span><br />';
					resultDiv += '<div>POST test: <span class="' + post_colour + '">' + post_result + '</span><br />';
					$("#connection_test_" + id).html(resultDiv);
					//$("#connection_test_" + id).html('<span class="green bold" title="Connection established, correct response received.">OK</span>');
					break;
				case 2:
					$("#connection_test_" + id).html('<span class="red bold" title="There seems to be a connection issue. Make sure that the entered URL is correct and that the certificates are in order.">Server unreachable</span>');
					break;
				case 3:
					$("#connection_test_" + id).html('<span class="red bold" title="The server returned an unexpected result. Make sure that the provided URL (or certificate if it applies) are correct.">Unexpected error</span>');
					break;
				case 4:
					$("#connection_test_" + id).html('<span class="red bold" title="Authentication failed due to incorrect authentication key or insufficient privileges on the remote instance.">Authentication failed</span>');
					break;
				case 5:
					$("#connection_test_" + id).html('<span class="red bold" title="Authentication failed because the sync user is expected to change passwords. Log into the remote MISP to rectify this.">Password change required</span>');
					break;
				case 6:
					$("#connection_test_" + id).html('<span class="red bold" title="Authentication failed because the sync user on the remote has not accepted the terms of use. Log into the remote MISP to rectify this.">Terms not accepted</span>');
					break;
				case 7:
					$("#connection_test_" + id).html('<span class="red bold" title="The user account on the remote instance is not a sync user.">Remote user not a sync user</span>');
					break;
			}
		}
	});
};

module.exports.pgpChoiceSelect = function (uri) {
	$("#popover_form").fadeOut();
	$("#gray_out").fadeOut();
	$.ajax({
		type: "get",
		url: "https://pgp.mit.edu/" + uri,
		success: function success(data) {
			var result = data.split("<pre>")[1].split("</pre>")[0];
			$("#UserGpgkey").val(result);
			showMessage('success', "Key found!");
		},
		error: function error(data, textStatus, errorThrown) {
			showMessage('fail', textStatus + ": " + errorThrown);
		}
	});
};

module.exports.lookupPGPKey = function (emailFieldName) {
	simplePopup("/users/fetchPGPKey/" + $('#' + emailFieldName).val());
};

module.exports.zeroMQServerAction = function (action) {
	$.ajax({
		type: "get",
		url: "/servers/" + action + "ZeroMQServer/",
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data) {
			$(".loading").hide();
			if (action !== 'status') {
				window.location.reload();
			} else {
				$("#confirmation_box").html(data);
				openPopup("#confirmation_box");
			}
		},
		error: function error(data, textStatus, errorThrown) {
			showMessage('fail', textStatus + ": " + errorThrown);
		}
	});
};

module.exports.convertServerFilterRules = function (rules) {
	validOptions.forEach(function (type) {
		container = "#" + modelContext + type.ucfirst() + "Rules";
		if ($(container).val() != '') rules[type] = JSON.parse($(container).val());
	});
	serverRuleUpdate();
	return rules;
};

module.exports.serverRuleUpdate = function () {
	var statusOptions = ["OR", "NOT"];
	validOptions.forEach(function (type) {
		validFields.forEach(function (field) {
			if (type === 'push') {
				var indexedList = {};
				window[field].forEach(function (item) {
					indexedList[item.id] = item.name;
				});
			}
			statusOptions.forEach(function (status) {
				if (rules[type][field][status].length > 0) {
					$('#' + type + '_' + field + '_' + status).show();
					var t = '';
					rules[type][field][status].forEach(function (item) {
						if (t.length > 0) t += ', ';
						if (type === 'pull') t += item;else t += indexedList[item];
					});
					$('#' + type + '_' + field + '_' + status + '_text').text(t);
				} else {
					$('#' + type + '_' + field + '_' + status).hide();
				}
			});
		});
	});
	serverRuleGenerateJSON();
};

module.exports.serverRuleFormActivate = function (type) {
	if (type != 'pull' && type != 'push') return false;
	$('.server_rule_popover').hide();
	$('#gray_out').fadeIn();
	$('#server_' + type + '_rule_popover').show();
};

module.exports.serverRuleCancel = function () {
	$("#gray_out").fadeOut();
	$(".server_rule_popover").fadeOut();
};

module.exports.serverRuleGenerateJSON = function () {
	validOptions.forEach(function (type) {
		if ($('#Server' + type.ucfirst() + "Rules").length) {
			$('#Server' + type.ucfirst() + "Rules").val(JSON.stringify(rules[type]));
		} else {
			$('#Feed' + type.ucfirst() + "Rules").val(JSON.stringify(rules[type]));
		}
	});
};

module.exports.serverRulePopulateTagPicklist = function () {
	var fields = ["tags", "orgs"];
	var target = "";
	fields.forEach(function (field) {
		target = "";
		window[field].forEach(function (element) {
			if ($.inArray(element.id, rules["push"][field]["OR"]) != -1) target = "#" + field + "pushLeftValues";else if ($.inArray(element.id, rules["push"][field]["NOT"]) != -1) target = "#" + field + "pushRightValues";else target = "#" + field + "pushMiddleValues";
			$(target).append($('<option/>', {
				value: element.id,
				text: element.name
			}));
		});
		target = "#" + field + "pullLeftValues";
		rules["pull"][field]["OR"].forEach(function (t) {
			$(target).append($('<option/>', {
				value: t,
				text: t
			}));
		});
		target = "#" + field + "pullRightValues";
		rules["pull"][field]["NOT"].forEach(function (t) {
			$(target).append($('<option/>', {
				value: t,
				text: t
			}));
		});
	});
};

module.exports.submitServerRulePopulateTagPicklistValues = function (context) {
	validFields.forEach(function (field) {
		rules[context][field]["OR"] = [];
		$("#" + field + context + "LeftValues option").each(function () {
			rules[context][field]["OR"].push($(this).val());
		});
		rules[context][field]["NOT"] = [];
		$("#" + field + context + "RightValues option").each(function () {
			rules[context][field]["NOT"].push($(this).val());
		});
	});

	$('#server_' + context + '_rule_popover').fadeOut();
	$('#gray_out').fadeOut();
	serverRuleUpdate();
};

// type = pull/push, field = tags/orgs, from = Left/Middle/Right, to = Left/Middle/Right
module.exports.serverRuleMoveFilter = function (type, field, from, to) {
	var opposites = { "Left": "Right", "Right": "Left" };
	// first fetch the value
	var value = "";
	if (type == "pull" && from == "Middle") {
		var doInsert = true;
		value = $("#" + field + type + "NewValue").val();
		if (value.length !== 0 && value.trim()) {
			$("#" + field + type + to + "Values" + " option").each(function () {
				if (value == $(this).val()) doInsert = false;
			});
			$("#" + field + type + opposites[to] + "Values" + " option").each(function () {
				if (value == $(this).val()) $(this).remove();
			});
			if (doInsert) {
				$("#" + field + type + to + "Values").append($('<option/>', {
					value: value,
					text: value
				}));
			}
		}
		$("#" + field + type + "NewValue").val('');
	} else {
		$("#" + field + type + from + "Values option:selected").each(function () {
			if (type != "pull" || to != "Middle") {
				value = $(this).val();
				text = $(this).text();
				$("#" + field + type + to + "Values").append($('<option/>', {
					value: value,
					text: text
				}));
			}
			$(this).remove();
		});
	}
};

module.exports.syncUserSelected = function () {
	if ($('#UserRoleId :selected').val() in syncRoles) {
		$('#syncServers').show();
	} else {
		$('#syncServers').hide();
	}
};

module.exports.filterAttributes = function (filter, id) {
	url = "/events/viewEventAttributes/" + id + "/attributeFilter:" + filter;
	if (deleted) url += '/deleted:true';
	$.ajax({
		type: "get",
		url: url,
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data) {
			$("#attributes_div").html(data);
			$(".loading").hide();
		},
		error: function error() {
			showMessage('fail', 'Something went wrong - could not fetch attributes.');
		}
	});
};

module.exports.toggleDeletedAttributes = function (url) {
	url = url.replace(/view\//i, 'viewEventAttributes/');
	if (url.indexOf('deleted:') > -1) {
		url = url.replace(/\/deleted:[^\/]*/i, '');
	} else {
		url = url + '/deleted:true';
	}
	$.ajax({
		type: "get",
		url: url,
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data) {
			$("#attributes_div").html(data);
			$(".loading").hide();
		},
		error: function error() {
			showMessage('fail', 'Something went wrong - could not fetch attributes.');
		}
	});
};

module.exports.mergeOrganisationUpdate = function () {
	var orgTypeOptions = ['local', 'external'];
	var orgTypeSelects = ['OrganisationOrgsLocal', 'OrganisationOrgsExternal'];
	orgType = orgTypeSelects[$('#OrganisationTargetType').val()];
	orgID = $('#' + orgType).val();
	org = orgArray[orgTypeOptions[$('#OrganisationTargetType').val()]][orgID]['Organisation'];
	$('#org_id').text(org['id']);
	$('#org_name').text(org['name']);
	$('#org_uuid').text(org['uuid']);
	$('#org_local').text(orgTypeOptions[$('#OrganisationTargetType').val()]);
};

module.exports.mergeOrganisationTypeToggle = function () {
	if ($('#OrganisationTargetType').val() == 0) {
		$('#orgsLocal').show();
		$('#orgsExternal').hide();
	} else {
		$('#orgsLocal').hide();
		$('#orgsExternal').show();
	}
};

module.exports.feedDistributionChange = function () {
	if ($('#FeedDistribution').val() == 4) $('#SGContainer').show();else $('#SGContainer').hide();
};

module.exports.checkUserPasswordEnabled = function () {
	if ($('#UserEnablePassword').is(':checked')) {
		$('#PasswordDiv').show();
	} else {
		$('#PasswordDiv').hide();
	}
};

module.exports.checkUserExternalAuth = function () {
	if ($('#UserExternalAuthRequired').is(':checked')) {
		$('#externalAuthDiv').show();
		$('#passwordDivDiv').hide();
	} else {
		$('#externalAuthDiv').hide();
		$('#passwordDivDiv').show();
	}
};

module.exports.toggleSettingSubGroup = function (group) {
	$('.subGroup_' + group).toggle();
};

module.exports.runHoverLookup = function (type, id) {
	$.ajax({
		success: function success(html) {
			ajaxResults[type + "_" + id] = html;
			$('.popover').remove();
			$('#' + type + '_' + id + '_container').popover({
				title: 'Lookup results:',
				content: html,
				placement: 'left',
				html: true,
				trigger: 'hover',
				container: 'body'
			}).popover('show');
		},
		cache: false,
		url: "/attributes/hoverEnrichment/" + id
	});
};

$(".eventViewAttributeHover").mouseenter(function () {
	$('.popover').remove();
	type = $(this).attr('data-object-type');
	id = $(this).attr('data-object-id');
	if (type + "_" + id in ajaxResults) {
		$('#' + type + '_' + id + '_container').popover({
			title: 'Lookup results:',
			content: ajaxResults[type + "_" + id],
			placement: 'left',
			html: true,
			trigger: 'hover',
			container: 'body'
		}).popover('show');
	} else {
		timer = setTimeout(function () {
			runHoverLookup(type, id);
		}, 500);
	}
}).mouseleave(function () {
	clearTimeout(timer);
});

$(".queryPopover").click(function () {
	url = $(this).data('url');
	id = $(this).data('id');
	$.get(url + '/' + id, function (data) {
		$('#popover_form').html(data);
		openPopup('#popover_form');
	});
});

module.exports.serverOwnerOrganisationChange = function (host_org_id) {
	if ($('#ServerOrganisationType').val() == "0" && $('#ServerLocal').val() == host_org_id) {
		$('#InternalDiv').show();
	} else {
		$('#ServerInternal').prop("checked", false);
		$('#InternalDiv').hide();
	}
};

module.exports.requestAPIAccess = function () {
	url = "/users/request_API/";
	$.ajax({
		type: "get",
		url: url,
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data) {
			$(".loading").hide();
			handleGenericAjaxResponse(data);
		},
		error: function error() {
			showMessage('fail', 'Something went wrong - could not request API access.');
		}
	});
};

module.exports.initPopoverContent = function (context) {
	for (var property in formInfoFields) {
		if (formInfoFields.hasOwnProperty(property)) {
			$('#' + property + 'InfoPopover').popover("destroy").popover({
				placement: 'right',
				html: 'true',
				trigger: 'hover',
				content: getFormInfoContent(property, '#' + context + formInfoFields[property])
			});
		}
	}
};

module.exports.getFormInfoContent = function (property, field) {
	var content = window[property + 'FormInfoValues'][$(field).val()];
	if (content === undefined || content === null) {
		return 'N/A';
	}
	return content;
};

module.exports.formCategoryChanged = function (id) {
	// fill in the types
	var options = $('#AttributeType').prop('options');
	$('option', $('#AttributeType')).remove();
	$.each(category_type_mapping[$('#AttributeCategory').val()], function (val, text) {
		options[options.length] = new Option(text, val);
	});
	// enable the form element
	$('#AttributeType').prop('disabled', false);
};

module.exports.malwareCheckboxSetter = function (context) {
	idDiv = "#" + context + "Category" + 'Div';
	var value = $("#" + context + "Category").val(); // get the selected value
	// set the malware checkbox if the category is in the zip types
	$("#" + context + "Malware").prop('checked', formZipTypeValues[value] == "true");
};

module.exports.feedFormUpdate = function () {
	$('.optionalField').hide();
	switch ($('#FeedSourceFormat').val()) {
		case 'freetext':
			$('#TargetDiv').show();
			$('#OverrideIdsDiv').show();
			$('#PublishDiv').show();
			if ($('#FeedTarget').val() != 0) {
				$('#TargetEventDiv').show();
				$('#DeltaMergeDiv').show();
			}
			$('#settingsCommonExcluderegexDiv').show();
			break;
		case 'csv':
			$('#TargetDiv').show();
			$('#OverrideIdsDiv').show();
			$('#PublishDiv').show();
			if ($('#FeedTarget').val() != 0) {
				$('#TargetEventDiv').show();
				$('#DeltaMergeDiv').show();
			}
			$('#settingsCsvValueDiv').show();
			$('#settingsCsvDelimiterDiv').show();
			$('#settingsCommonExcluderegexDiv').show();
			break;
	}
	if ($('#FeedInputSource').val() == 'local') {
		$('#DeleteLocalFileDiv').show();
	} else {
		$('#DeleteLocalFileDiv').hide();
	}
};

$('.servers_default_role_checkbox').click(function () {
	var id = $(this).data("id");
	var state = $(this).is(":checked");
	$(".servers_default_role_checkbox").not(this).attr('checked', false);
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data, textStatus) {
			handleGenericAjaxResponse(data);
		},
		complete: function complete() {
			$(".loading").hide();
		},
		type: "get",
		cache: false,
		url: '/admin/roles/set_default/' + (state ? id : "")
	});
});

module.exports.setContextFields = function () {
	if (showContext) {
		$('.context').show();
		$('#show_context').addClass("attribute_filter_text_active");
		$('#show_context').removeClass("attribute_filter_text");
	} else {
		$('.context').hide();
		$('#show_context').addClass("attribute_filter_text");
		$('#show_context').removeClass("attribute_filter_text_active");
	}
};

module.exports.toggleContextFields = function () {
	if (!showContext) {
		showContext = true;
	} else {
		showContext = false;
	}
	setContextFields();
};

module.exports.checkOrphanedAttributes = function () {
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data, textStatus) {
			var color = 'red';
			var text = ' (Removal recommended)';
			if (data == '0') {
				color = 'green';
				text = ' (OK)';
			}
			$("#orphanedAttributeCount").html('<span class="' + color + '">' + data + text + '</span>');
		},
		complete: function complete() {
			$(".loading").hide();
		},
		type: "get",
		cache: false,
		url: "/attributes/checkOrphanedAttributes/"
	});
};

module.exports.loadTagTreemap = function () {
	$.ajax({
		async: true,
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data, textStatus) {
			$(".treemapdiv").html(data);
		},
		complete: function complete() {
			$(".loading").hide();
		},
		type: "get",
		cache: false,
		url: "/users/tagStatisticsGraph"
	});
};

module.exports.loadSightingsData = function (timestamp) {
	url = "/sightings/toplist";
	if (timestamp != undefined) {
		url = url + '/' + timestamp;
	}
	$.ajax({
		async: true,
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data, textStatus) {
			$(".sightingsdiv").html(data);
		},
		complete: function complete() {
			$(".loading").hide();
		},
		type: "get",
		cache: false,
		url: url
	});
};

module.exports.quickEditEvent = function (id, field) {
	$.ajax({
		async: true,
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		success: function success(data, textStatus) {
			$("#" + field + "Field").html(data);
		},
		complete: function complete() {
			$(".loading").hide();
		},
		type: "get",
		cache: false,
		url: "/events/quickEdit/" + id + "/" + field
	});
};

module.exports.selectAllInbetween = function (last, current) {
	if (last === false || last == current) return false;
	if (last < current) {
		var temp = current;
		current = last;
		last = temp;
	}
	$('.select_proposal, .select_attribute').each(function () {
		if ($(this).parent().data('position') > current && $(this).parent().data('position') < last) {
			$(this).prop('checked', true);
		}
	});
};

$('.galaxy-toggle-button').click(function () {
	var element = $(this).data('toggle-type');
	if ($(this).children('span').hasClass('icon-minus')) {
		$(this).children('span').addClass('icon-plus');
		$(this).children('span').removeClass('icon-minus');
		$('#' + element + '_div').hide();
	} else {
		$(this).children('span').removeClass('icon-plus');
		$(this).children('span').addClass('icon-minus');
		$('#' + element + '_div').show();
	}
});

$('#addGalaxy').click(function () {
	getPopup($(this).data('event-id'), 'galaxies', 'selectGalaxy');
});

module.exports.quickSubmitGalaxyForm = function (event_id, cluster_id) {
	$('#GalaxyTargetId').val(cluster_id);
	$('#GalaxySelectClusterForm').submit();
	return false;
};

module.exports.checkAndSetPublishedInfo = function () {
	var id = $('#hiddenSideMenuData').data('event-id');
	$.get("/events/checkPublishedStatus/" + id, function (data) {
		if (data == 1) {
			$('.published').removeClass('hidden');
			$('.not-published').addClass('hidden');
		} else {
			$('.published').addClass('hidden');
			$('.not-published').removeClass('hidden');
		}
	});
};

$(document).keyup(function (e) {
	if (e.keyCode === 27) {
		$("#gray_out").fadeOut();
		$("#popover_form").fadeOut();
		$("#screenshot_box").fadeOut();
		$("#confirmation_box").fadeOut();
		$(".loading").hide();
		resetForms();
	}
});

module.exports.closeScreenshot = function () {
	$("#screenshot_box").fadeOut();
	$("#gray_out").fadeOut();
};

module.exports.loadSightingGraph = function (id, scope) {
	$.get("/sightings/viewSightings/" + id + "/" + scope, function (data) {
		$("#sightingsData").html(data);
	});
};

module.exports.checkRolePerms = function () {
	if ($("#RolePermission").val() == '0' || $("#RolePermission").val() == '1') {
		$('.readonlydisabled').prop('checked', false);
		$('.readonlydisabled').hide();
	} else {
		$('.readonlydisabled').show();
		$('.permFlags').show();
	}
	if ($("#RolePermSiteAdmin").prop('checked')) {
		$('.checkbox').prop('checked', true);
	}
};

// clicking on an element with this class will select all of its contents in a
// single click
$('.quickSelect').click(function () {
	var range = document.createRange();
	var selection = window.getSelection();
	range.selectNodeContents(this);
	selection.removeAllRanges();
	selection.addRange(range);
});

module.exports.updateMISP = function () {
	$.get("/servers/update", function (data) {
		$("#confirmation_box").html(data);
		openPopup("#confirmation_box");
	});
};

module.exports.submitMISPUpdate = function () {
	var formData = $('#PromptForm').serialize();
	$.ajax({
		beforeSend: function beforeSend(XMLHttpRequest) {
			$(".loading").show();
		},
		data: formData,
		success: function success(data, textStatus) {
			$('#gitResult').text(data);
			$('#gitResult').removeClass('hidden');
		},
		complete: function complete() {
			$(".loading").hide();
			$("#confirmation_box").fadeOut();
			$("#gray_out").fadeOut();
		},
		type: "post",
		cache: false,
		url: "/servers/update"
	});
}(function () {
	"use strict";

	$(".datepicker").datepicker({
		format: 'yyyy-mm-dd'
	});
}());

},{"jquery-ui/ui/widgets/datepicker":3}],3:[function(require,module,exports){
// jscs:disable maximumLineLength
/* jscs:disable requireCamelCaseOrUpperCaseIdentifiers */
/*!
 * jQuery UI Datepicker 1.12.1
 * http://jqueryui.com
 *
 * Copyright jQuery Foundation and other contributors
 * Released under the MIT license.
 * http://jquery.org/license
 */

//>>label: Datepicker
//>>group: Widgets
//>>description: Displays a calendar from an input or inline for selecting dates.
//>>docs: http://api.jqueryui.com/datepicker/
//>>demos: http://jqueryui.com/datepicker/
//>>css.structure: ../../themes/base/core.css
//>>css.structure: ../../themes/base/datepicker.css
//>>css.theme: ../../themes/base/theme.css

( function( factory ) {
	if ( typeof define === "function" && define.amd ) {

		// AMD. Register as an anonymous module.
		define( [
			"jquery",
			"../version",
			"../keycode"
		], factory );
	} else {

		// Browser globals
		factory( jQuery );
	}
}( function( $ ) {

$.extend( $.ui, { datepicker: { version: "1.12.1" } } );

var datepicker_instActive;

function datepicker_getZindex( elem ) {
	var position, value;
	while ( elem.length && elem[ 0 ] !== document ) {

		// Ignore z-index if position is set to a value where z-index is ignored by the browser
		// This makes behavior of this function consistent across browsers
		// WebKit always returns auto if the element is positioned
		position = elem.css( "position" );
		if ( position === "absolute" || position === "relative" || position === "fixed" ) {

			// IE returns 0 when zIndex is not specified
			// other browsers return a string
			// we ignore the case of nested elements with an explicit value of 0
			// <div style="z-index: -10;"><div style="z-index: 0;"></div></div>
			value = parseInt( elem.css( "zIndex" ), 10 );
			if ( !isNaN( value ) && value !== 0 ) {
				return value;
			}
		}
		elem = elem.parent();
	}

	return 0;
}
/* Date picker manager.
   Use the singleton instance of this class, $.datepicker, to interact with the date picker.
   Settings for (groups of) date pickers are maintained in an instance object,
   allowing multiple different settings on the same page. */

function Datepicker() {
	this._curInst = null; // The current instance in use
	this._keyEvent = false; // If the last event was a key event
	this._disabledInputs = []; // List of date picker inputs that have been disabled
	this._datepickerShowing = false; // True if the popup picker is showing , false if not
	this._inDialog = false; // True if showing within a "dialog", false if not
	this._mainDivId = "ui-datepicker-div"; // The ID of the main datepicker division
	this._inlineClass = "ui-datepicker-inline"; // The name of the inline marker class
	this._appendClass = "ui-datepicker-append"; // The name of the append marker class
	this._triggerClass = "ui-datepicker-trigger"; // The name of the trigger marker class
	this._dialogClass = "ui-datepicker-dialog"; // The name of the dialog marker class
	this._disableClass = "ui-datepicker-disabled"; // The name of the disabled covering marker class
	this._unselectableClass = "ui-datepicker-unselectable"; // The name of the unselectable cell marker class
	this._currentClass = "ui-datepicker-current-day"; // The name of the current day marker class
	this._dayOverClass = "ui-datepicker-days-cell-over"; // The name of the day hover marker class
	this.regional = []; // Available regional settings, indexed by language code
	this.regional[ "" ] = { // Default regional settings
		closeText: "Done", // Display text for close link
		prevText: "Prev", // Display text for previous month link
		nextText: "Next", // Display text for next month link
		currentText: "Today", // Display text for current month link
		monthNames: [ "January","February","March","April","May","June",
			"July","August","September","October","November","December" ], // Names of months for drop-down and formatting
		monthNamesShort: [ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" ], // For formatting
		dayNames: [ "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" ], // For formatting
		dayNamesShort: [ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" ], // For formatting
		dayNamesMin: [ "Su","Mo","Tu","We","Th","Fr","Sa" ], // Column headings for days starting at Sunday
		weekHeader: "Wk", // Column header for week of the year
		dateFormat: "mm/dd/yy", // See format options on parseDate
		firstDay: 0, // The first day of the week, Sun = 0, Mon = 1, ...
		isRTL: false, // True if right-to-left language, false if left-to-right
		showMonthAfterYear: false, // True if the year select precedes month, false for month then year
		yearSuffix: "" // Additional text to append to the year in the month headers
	};
	this._defaults = { // Global defaults for all the date picker instances
		showOn: "focus", // "focus" for popup on focus,
			// "button" for trigger button, or "both" for either
		showAnim: "fadeIn", // Name of jQuery animation for popup
		showOptions: {}, // Options for enhanced animations
		defaultDate: null, // Used when field is blank: actual date,
			// +/-number for offset from today, null for today
		appendText: "", // Display text following the input box, e.g. showing the format
		buttonText: "...", // Text for trigger button
		buttonImage: "", // URL for trigger button image
		buttonImageOnly: false, // True if the image appears alone, false if it appears on a button
		hideIfNoPrevNext: false, // True to hide next/previous month links
			// if not applicable, false to just disable them
		navigationAsDateFormat: false, // True if date formatting applied to prev/today/next links
		gotoCurrent: false, // True if today link goes back to current selection instead
		changeMonth: false, // True if month can be selected directly, false if only prev/next
		changeYear: false, // True if year can be selected directly, false if only prev/next
		yearRange: "c-10:c+10", // Range of years to display in drop-down,
			// either relative to today's year (-nn:+nn), relative to currently displayed year
			// (c-nn:c+nn), absolute (nnnn:nnnn), or a combination of the above (nnnn:-n)
		showOtherMonths: false, // True to show dates in other months, false to leave blank
		selectOtherMonths: false, // True to allow selection of dates in other months, false for unselectable
		showWeek: false, // True to show week of the year, false to not show it
		calculateWeek: this.iso8601Week, // How to calculate the week of the year,
			// takes a Date and returns the number of the week for it
		shortYearCutoff: "+10", // Short year values < this are in the current century,
			// > this are in the previous century,
			// string value starting with "+" for current year + value
		minDate: null, // The earliest selectable date, or null for no limit
		maxDate: null, // The latest selectable date, or null for no limit
		duration: "fast", // Duration of display/closure
		beforeShowDay: null, // Function that takes a date and returns an array with
			// [0] = true if selectable, false if not, [1] = custom CSS class name(s) or "",
			// [2] = cell title (optional), e.g. $.datepicker.noWeekends
		beforeShow: null, // Function that takes an input field and
			// returns a set of custom settings for the date picker
		onSelect: null, // Define a callback function when a date is selected
		onChangeMonthYear: null, // Define a callback function when the month or year is changed
		onClose: null, // Define a callback function when the datepicker is closed
		numberOfMonths: 1, // Number of months to show at a time
		showCurrentAtPos: 0, // The position in multipe months at which to show the current month (starting at 0)
		stepMonths: 1, // Number of months to step back/forward
		stepBigMonths: 12, // Number of months to step back/forward for the big links
		altField: "", // Selector for an alternate field to store selected dates into
		altFormat: "", // The date format to use for the alternate field
		constrainInput: true, // The input is constrained by the current date format
		showButtonPanel: false, // True to show button panel, false to not show it
		autoSize: false, // True to size the input for the date format, false to leave as is
		disabled: false // The initial disabled state
	};
	$.extend( this._defaults, this.regional[ "" ] );
	this.regional.en = $.extend( true, {}, this.regional[ "" ] );
	this.regional[ "en-US" ] = $.extend( true, {}, this.regional.en );
	this.dpDiv = datepicker_bindHover( $( "<div id='" + this._mainDivId + "' class='ui-datepicker ui-widget ui-widget-content ui-helper-clearfix ui-corner-all'></div>" ) );
}

$.extend( Datepicker.prototype, {
	/* Class name added to elements to indicate already configured with a date picker. */
	markerClassName: "hasDatepicker",

	//Keep track of the maximum number of rows displayed (see #7043)
	maxRows: 4,

	// TODO rename to "widget" when switching to widget factory
	_widgetDatepicker: function() {
		return this.dpDiv;
	},

	/* Override the default settings for all instances of the date picker.
	 * @param  settings  object - the new settings to use as defaults (anonymous object)
	 * @return the manager object
	 */
	setDefaults: function( settings ) {
		datepicker_extendRemove( this._defaults, settings || {} );
		return this;
	},

	/* Attach the date picker to a jQuery selection.
	 * @param  target	element - the target input field or division or span
	 * @param  settings  object - the new settings to use for this date picker instance (anonymous)
	 */
	_attachDatepicker: function( target, settings ) {
		var nodeName, inline, inst;
		nodeName = target.nodeName.toLowerCase();
		inline = ( nodeName === "div" || nodeName === "span" );
		if ( !target.id ) {
			this.uuid += 1;
			target.id = "dp" + this.uuid;
		}
		inst = this._newInst( $( target ), inline );
		inst.settings = $.extend( {}, settings || {} );
		if ( nodeName === "input" ) {
			this._connectDatepicker( target, inst );
		} else if ( inline ) {
			this._inlineDatepicker( target, inst );
		}
	},

	/* Create a new instance object. */
	_newInst: function( target, inline ) {
		var id = target[ 0 ].id.replace( /([^A-Za-z0-9_\-])/g, "\\\\$1" ); // escape jQuery meta chars
		return { id: id, input: target, // associated target
			selectedDay: 0, selectedMonth: 0, selectedYear: 0, // current selection
			drawMonth: 0, drawYear: 0, // month being drawn
			inline: inline, // is datepicker inline or not
			dpDiv: ( !inline ? this.dpDiv : // presentation div
			datepicker_bindHover( $( "<div class='" + this._inlineClass + " ui-datepicker ui-widget ui-widget-content ui-helper-clearfix ui-corner-all'></div>" ) ) ) };
	},

	/* Attach the date picker to an input field. */
	_connectDatepicker: function( target, inst ) {
		var input = $( target );
		inst.append = $( [] );
		inst.trigger = $( [] );
		if ( input.hasClass( this.markerClassName ) ) {
			return;
		}
		this._attachments( input, inst );
		input.addClass( this.markerClassName ).on( "keydown", this._doKeyDown ).
			on( "keypress", this._doKeyPress ).on( "keyup", this._doKeyUp );
		this._autoSize( inst );
		$.data( target, "datepicker", inst );

		//If disabled option is true, disable the datepicker once it has been attached to the input (see ticket #5665)
		if ( inst.settings.disabled ) {
			this._disableDatepicker( target );
		}
	},

	/* Make attachments based on settings. */
	_attachments: function( input, inst ) {
		var showOn, buttonText, buttonImage,
			appendText = this._get( inst, "appendText" ),
			isRTL = this._get( inst, "isRTL" );

		if ( inst.append ) {
			inst.append.remove();
		}
		if ( appendText ) {
			inst.append = $( "<span class='" + this._appendClass + "'>" + appendText + "</span>" );
			input[ isRTL ? "before" : "after" ]( inst.append );
		}

		input.off( "focus", this._showDatepicker );

		if ( inst.trigger ) {
			inst.trigger.remove();
		}

		showOn = this._get( inst, "showOn" );
		if ( showOn === "focus" || showOn === "both" ) { // pop-up date picker when in the marked field
			input.on( "focus", this._showDatepicker );
		}
		if ( showOn === "button" || showOn === "both" ) { // pop-up date picker when button clicked
			buttonText = this._get( inst, "buttonText" );
			buttonImage = this._get( inst, "buttonImage" );
			inst.trigger = $( this._get( inst, "buttonImageOnly" ) ?
				$( "<img/>" ).addClass( this._triggerClass ).
					attr( { src: buttonImage, alt: buttonText, title: buttonText } ) :
				$( "<button type='button'></button>" ).addClass( this._triggerClass ).
					html( !buttonImage ? buttonText : $( "<img/>" ).attr(
					{ src:buttonImage, alt:buttonText, title:buttonText } ) ) );
			input[ isRTL ? "before" : "after" ]( inst.trigger );
			inst.trigger.on( "click", function() {
				if ( $.datepicker._datepickerShowing && $.datepicker._lastInput === input[ 0 ] ) {
					$.datepicker._hideDatepicker();
				} else if ( $.datepicker._datepickerShowing && $.datepicker._lastInput !== input[ 0 ] ) {
					$.datepicker._hideDatepicker();
					$.datepicker._showDatepicker( input[ 0 ] );
				} else {
					$.datepicker._showDatepicker( input[ 0 ] );
				}
				return false;
			} );
		}
	},

	/* Apply the maximum length for the date format. */
	_autoSize: function( inst ) {
		if ( this._get( inst, "autoSize" ) && !inst.inline ) {
			var findMax, max, maxI, i,
				date = new Date( 2009, 12 - 1, 20 ), // Ensure double digits
				dateFormat = this._get( inst, "dateFormat" );

			if ( dateFormat.match( /[DM]/ ) ) {
				findMax = function( names ) {
					max = 0;
					maxI = 0;
					for ( i = 0; i < names.length; i++ ) {
						if ( names[ i ].length > max ) {
							max = names[ i ].length;
							maxI = i;
						}
					}
					return maxI;
				};
				date.setMonth( findMax( this._get( inst, ( dateFormat.match( /MM/ ) ?
					"monthNames" : "monthNamesShort" ) ) ) );
				date.setDate( findMax( this._get( inst, ( dateFormat.match( /DD/ ) ?
					"dayNames" : "dayNamesShort" ) ) ) + 20 - date.getDay() );
			}
			inst.input.attr( "size", this._formatDate( inst, date ).length );
		}
	},

	/* Attach an inline date picker to a div. */
	_inlineDatepicker: function( target, inst ) {
		var divSpan = $( target );
		if ( divSpan.hasClass( this.markerClassName ) ) {
			return;
		}
		divSpan.addClass( this.markerClassName ).append( inst.dpDiv );
		$.data( target, "datepicker", inst );
		this._setDate( inst, this._getDefaultDate( inst ), true );
		this._updateDatepicker( inst );
		this._updateAlternate( inst );

		//If disabled option is true, disable the datepicker before showing it (see ticket #5665)
		if ( inst.settings.disabled ) {
			this._disableDatepicker( target );
		}

		// Set display:block in place of inst.dpDiv.show() which won't work on disconnected elements
		// http://bugs.jqueryui.com/ticket/7552 - A Datepicker created on a detached div has zero height
		inst.dpDiv.css( "display", "block" );
	},

	/* Pop-up the date picker in a "dialog" box.
	 * @param  input element - ignored
	 * @param  date	string or Date - the initial date to display
	 * @param  onSelect  function - the function to call when a date is selected
	 * @param  settings  object - update the dialog date picker instance's settings (anonymous object)
	 * @param  pos int[2] - coordinates for the dialog's position within the screen or
	 *					event - with x/y coordinates or
	 *					leave empty for default (screen centre)
	 * @return the manager object
	 */
	_dialogDatepicker: function( input, date, onSelect, settings, pos ) {
		var id, browserWidth, browserHeight, scrollX, scrollY,
			inst = this._dialogInst; // internal instance

		if ( !inst ) {
			this.uuid += 1;
			id = "dp" + this.uuid;
			this._dialogInput = $( "<input type='text' id='" + id +
				"' style='position: absolute; top: -100px; width: 0px;'/>" );
			this._dialogInput.on( "keydown", this._doKeyDown );
			$( "body" ).append( this._dialogInput );
			inst = this._dialogInst = this._newInst( this._dialogInput, false );
			inst.settings = {};
			$.data( this._dialogInput[ 0 ], "datepicker", inst );
		}
		datepicker_extendRemove( inst.settings, settings || {} );
		date = ( date && date.constructor === Date ? this._formatDate( inst, date ) : date );
		this._dialogInput.val( date );

		this._pos = ( pos ? ( pos.length ? pos : [ pos.pageX, pos.pageY ] ) : null );
		if ( !this._pos ) {
			browserWidth = document.documentElement.clientWidth;
			browserHeight = document.documentElement.clientHeight;
			scrollX = document.documentElement.scrollLeft || document.body.scrollLeft;
			scrollY = document.documentElement.scrollTop || document.body.scrollTop;
			this._pos = // should use actual width/height below
				[ ( browserWidth / 2 ) - 100 + scrollX, ( browserHeight / 2 ) - 150 + scrollY ];
		}

		// Move input on screen for focus, but hidden behind dialog
		this._dialogInput.css( "left", ( this._pos[ 0 ] + 20 ) + "px" ).css( "top", this._pos[ 1 ] + "px" );
		inst.settings.onSelect = onSelect;
		this._inDialog = true;
		this.dpDiv.addClass( this._dialogClass );
		this._showDatepicker( this._dialogInput[ 0 ] );
		if ( $.blockUI ) {
			$.blockUI( this.dpDiv );
		}
		$.data( this._dialogInput[ 0 ], "datepicker", inst );
		return this;
	},

	/* Detach a datepicker from its control.
	 * @param  target	element - the target input field or division or span
	 */
	_destroyDatepicker: function( target ) {
		var nodeName,
			$target = $( target ),
			inst = $.data( target, "datepicker" );

		if ( !$target.hasClass( this.markerClassName ) ) {
			return;
		}

		nodeName = target.nodeName.toLowerCase();
		$.removeData( target, "datepicker" );
		if ( nodeName === "input" ) {
			inst.append.remove();
			inst.trigger.remove();
			$target.removeClass( this.markerClassName ).
				off( "focus", this._showDatepicker ).
				off( "keydown", this._doKeyDown ).
				off( "keypress", this._doKeyPress ).
				off( "keyup", this._doKeyUp );
		} else if ( nodeName === "div" || nodeName === "span" ) {
			$target.removeClass( this.markerClassName ).empty();
		}

		if ( datepicker_instActive === inst ) {
			datepicker_instActive = null;
		}
	},

	/* Enable the date picker to a jQuery selection.
	 * @param  target	element - the target input field or division or span
	 */
	_enableDatepicker: function( target ) {
		var nodeName, inline,
			$target = $( target ),
			inst = $.data( target, "datepicker" );

		if ( !$target.hasClass( this.markerClassName ) ) {
			return;
		}

		nodeName = target.nodeName.toLowerCase();
		if ( nodeName === "input" ) {
			target.disabled = false;
			inst.trigger.filter( "button" ).
				each( function() { this.disabled = false; } ).end().
				filter( "img" ).css( { opacity: "1.0", cursor: "" } );
		} else if ( nodeName === "div" || nodeName === "span" ) {
			inline = $target.children( "." + this._inlineClass );
			inline.children().removeClass( "ui-state-disabled" );
			inline.find( "select.ui-datepicker-month, select.ui-datepicker-year" ).
				prop( "disabled", false );
		}
		this._disabledInputs = $.map( this._disabledInputs,
			function( value ) { return ( value === target ? null : value ); } ); // delete entry
	},

	/* Disable the date picker to a jQuery selection.
	 * @param  target	element - the target input field or division or span
	 */
	_disableDatepicker: function( target ) {
		var nodeName, inline,
			$target = $( target ),
			inst = $.data( target, "datepicker" );

		if ( !$target.hasClass( this.markerClassName ) ) {
			return;
		}

		nodeName = target.nodeName.toLowerCase();
		if ( nodeName === "input" ) {
			target.disabled = true;
			inst.trigger.filter( "button" ).
				each( function() { this.disabled = true; } ).end().
				filter( "img" ).css( { opacity: "0.5", cursor: "default" } );
		} else if ( nodeName === "div" || nodeName === "span" ) {
			inline = $target.children( "." + this._inlineClass );
			inline.children().addClass( "ui-state-disabled" );
			inline.find( "select.ui-datepicker-month, select.ui-datepicker-year" ).
				prop( "disabled", true );
		}
		this._disabledInputs = $.map( this._disabledInputs,
			function( value ) { return ( value === target ? null : value ); } ); // delete entry
		this._disabledInputs[ this._disabledInputs.length ] = target;
	},

	/* Is the first field in a jQuery collection disabled as a datepicker?
	 * @param  target	element - the target input field or division or span
	 * @return boolean - true if disabled, false if enabled
	 */
	_isDisabledDatepicker: function( target ) {
		if ( !target ) {
			return false;
		}
		for ( var i = 0; i < this._disabledInputs.length; i++ ) {
			if ( this._disabledInputs[ i ] === target ) {
				return true;
			}
		}
		return false;
	},

	/* Retrieve the instance data for the target control.
	 * @param  target  element - the target input field or division or span
	 * @return  object - the associated instance data
	 * @throws  error if a jQuery problem getting data
	 */
	_getInst: function( target ) {
		try {
			return $.data( target, "datepicker" );
		}
		catch ( err ) {
			throw "Missing instance data for this datepicker";
		}
	},

	/* Update or retrieve the settings for a date picker attached to an input field or division.
	 * @param  target  element - the target input field or division or span
	 * @param  name	object - the new settings to update or
	 *				string - the name of the setting to change or retrieve,
	 *				when retrieving also "all" for all instance settings or
	 *				"defaults" for all global defaults
	 * @param  value   any - the new value for the setting
	 *				(omit if above is an object or to retrieve a value)
	 */
	_optionDatepicker: function( target, name, value ) {
		var settings, date, minDate, maxDate,
			inst = this._getInst( target );

		if ( arguments.length === 2 && typeof name === "string" ) {
			return ( name === "defaults" ? $.extend( {}, $.datepicker._defaults ) :
				( inst ? ( name === "all" ? $.extend( {}, inst.settings ) :
				this._get( inst, name ) ) : null ) );
		}

		settings = name || {};
		if ( typeof name === "string" ) {
			settings = {};
			settings[ name ] = value;
		}

		if ( inst ) {
			if ( this._curInst === inst ) {
				this._hideDatepicker();
			}

			date = this._getDateDatepicker( target, true );
			minDate = this._getMinMaxDate( inst, "min" );
			maxDate = this._getMinMaxDate( inst, "max" );
			datepicker_extendRemove( inst.settings, settings );

			// reformat the old minDate/maxDate values if dateFormat changes and a new minDate/maxDate isn't provided
			if ( minDate !== null && settings.dateFormat !== undefined && settings.minDate === undefined ) {
				inst.settings.minDate = this._formatDate( inst, minDate );
			}
			if ( maxDate !== null && settings.dateFormat !== undefined && settings.maxDate === undefined ) {
				inst.settings.maxDate = this._formatDate( inst, maxDate );
			}
			if ( "disabled" in settings ) {
				if ( settings.disabled ) {
					this._disableDatepicker( target );
				} else {
					this._enableDatepicker( target );
				}
			}
			this._attachments( $( target ), inst );
			this._autoSize( inst );
			this._setDate( inst, date );
			this._updateAlternate( inst );
			this._updateDatepicker( inst );
		}
	},

	// Change method deprecated
	_changeDatepicker: function( target, name, value ) {
		this._optionDatepicker( target, name, value );
	},

	/* Redraw the date picker attached to an input field or division.
	 * @param  target  element - the target input field or division or span
	 */
	_refreshDatepicker: function( target ) {
		var inst = this._getInst( target );
		if ( inst ) {
			this._updateDatepicker( inst );
		}
	},

	/* Set the dates for a jQuery selection.
	 * @param  target element - the target input field or division or span
	 * @param  date	Date - the new date
	 */
	_setDateDatepicker: function( target, date ) {
		var inst = this._getInst( target );
		if ( inst ) {
			this._setDate( inst, date );
			this._updateDatepicker( inst );
			this._updateAlternate( inst );
		}
	},

	/* Get the date(s) for the first entry in a jQuery selection.
	 * @param  target element - the target input field or division or span
	 * @param  noDefault boolean - true if no default date is to be used
	 * @return Date - the current date
	 */
	_getDateDatepicker: function( target, noDefault ) {
		var inst = this._getInst( target );
		if ( inst && !inst.inline ) {
			this._setDateFromField( inst, noDefault );
		}
		return ( inst ? this._getDate( inst ) : null );
	},

	/* Handle keystrokes. */
	_doKeyDown: function( event ) {
		var onSelect, dateStr, sel,
			inst = $.datepicker._getInst( event.target ),
			handled = true,
			isRTL = inst.dpDiv.is( ".ui-datepicker-rtl" );

		inst._keyEvent = true;
		if ( $.datepicker._datepickerShowing ) {
			switch ( event.keyCode ) {
				case 9: $.datepicker._hideDatepicker();
						handled = false;
						break; // hide on tab out
				case 13: sel = $( "td." + $.datepicker._dayOverClass + ":not(." +
									$.datepicker._currentClass + ")", inst.dpDiv );
						if ( sel[ 0 ] ) {
							$.datepicker._selectDay( event.target, inst.selectedMonth, inst.selectedYear, sel[ 0 ] );
						}

						onSelect = $.datepicker._get( inst, "onSelect" );
						if ( onSelect ) {
							dateStr = $.datepicker._formatDate( inst );

							// Trigger custom callback
							onSelect.apply( ( inst.input ? inst.input[ 0 ] : null ), [ dateStr, inst ] );
						} else {
							$.datepicker._hideDatepicker();
						}

						return false; // don't submit the form
				case 27: $.datepicker._hideDatepicker();
						break; // hide on escape
				case 33: $.datepicker._adjustDate( event.target, ( event.ctrlKey ?
							-$.datepicker._get( inst, "stepBigMonths" ) :
							-$.datepicker._get( inst, "stepMonths" ) ), "M" );
						break; // previous month/year on page up/+ ctrl
				case 34: $.datepicker._adjustDate( event.target, ( event.ctrlKey ?
							+$.datepicker._get( inst, "stepBigMonths" ) :
							+$.datepicker._get( inst, "stepMonths" ) ), "M" );
						break; // next month/year on page down/+ ctrl
				case 35: if ( event.ctrlKey || event.metaKey ) {
							$.datepicker._clearDate( event.target );
						}
						handled = event.ctrlKey || event.metaKey;
						break; // clear on ctrl or command +end
				case 36: if ( event.ctrlKey || event.metaKey ) {
							$.datepicker._gotoToday( event.target );
						}
						handled = event.ctrlKey || event.metaKey;
						break; // current on ctrl or command +home
				case 37: if ( event.ctrlKey || event.metaKey ) {
							$.datepicker._adjustDate( event.target, ( isRTL ? +1 : -1 ), "D" );
						}
						handled = event.ctrlKey || event.metaKey;

						// -1 day on ctrl or command +left
						if ( event.originalEvent.altKey ) {
							$.datepicker._adjustDate( event.target, ( event.ctrlKey ?
								-$.datepicker._get( inst, "stepBigMonths" ) :
								-$.datepicker._get( inst, "stepMonths" ) ), "M" );
						}

						// next month/year on alt +left on Mac
						break;
				case 38: if ( event.ctrlKey || event.metaKey ) {
							$.datepicker._adjustDate( event.target, -7, "D" );
						}
						handled = event.ctrlKey || event.metaKey;
						break; // -1 week on ctrl or command +up
				case 39: if ( event.ctrlKey || event.metaKey ) {
							$.datepicker._adjustDate( event.target, ( isRTL ? -1 : +1 ), "D" );
						}
						handled = event.ctrlKey || event.metaKey;

						// +1 day on ctrl or command +right
						if ( event.originalEvent.altKey ) {
							$.datepicker._adjustDate( event.target, ( event.ctrlKey ?
								+$.datepicker._get( inst, "stepBigMonths" ) :
								+$.datepicker._get( inst, "stepMonths" ) ), "M" );
						}

						// next month/year on alt +right
						break;
				case 40: if ( event.ctrlKey || event.metaKey ) {
							$.datepicker._adjustDate( event.target, +7, "D" );
						}
						handled = event.ctrlKey || event.metaKey;
						break; // +1 week on ctrl or command +down
				default: handled = false;
			}
		} else if ( event.keyCode === 36 && event.ctrlKey ) { // display the date picker on ctrl+home
			$.datepicker._showDatepicker( this );
		} else {
			handled = false;
		}

		if ( handled ) {
			event.preventDefault();
			event.stopPropagation();
		}
	},

	/* Filter entered characters - based on date format. */
	_doKeyPress: function( event ) {
		var chars, chr,
			inst = $.datepicker._getInst( event.target );

		if ( $.datepicker._get( inst, "constrainInput" ) ) {
			chars = $.datepicker._possibleChars( $.datepicker._get( inst, "dateFormat" ) );
			chr = String.fromCharCode( event.charCode == null ? event.keyCode : event.charCode );
			return event.ctrlKey || event.metaKey || ( chr < " " || !chars || chars.indexOf( chr ) > -1 );
		}
	},

	/* Synchronise manual entry and field/alternate field. */
	_doKeyUp: function( event ) {
		var date,
			inst = $.datepicker._getInst( event.target );

		if ( inst.input.val() !== inst.lastVal ) {
			try {
				date = $.datepicker.parseDate( $.datepicker._get( inst, "dateFormat" ),
					( inst.input ? inst.input.val() : null ),
					$.datepicker._getFormatConfig( inst ) );

				if ( date ) { // only if valid
					$.datepicker._setDateFromField( inst );
					$.datepicker._updateAlternate( inst );
					$.datepicker._updateDatepicker( inst );
				}
			}
			catch ( err ) {
			}
		}
		return true;
	},

	/* Pop-up the date picker for a given input field.
	 * If false returned from beforeShow event handler do not show.
	 * @param  input  element - the input field attached to the date picker or
	 *					event - if triggered by focus
	 */
	_showDatepicker: function( input ) {
		input = input.target || input;
		if ( input.nodeName.toLowerCase() !== "input" ) { // find from button/image trigger
			input = $( "input", input.parentNode )[ 0 ];
		}

		if ( $.datepicker._isDisabledDatepicker( input ) || $.datepicker._lastInput === input ) { // already here
			return;
		}

		var inst, beforeShow, beforeShowSettings, isFixed,
			offset, showAnim, duration;

		inst = $.datepicker._getInst( input );
		if ( $.datepicker._curInst && $.datepicker._curInst !== inst ) {
			$.datepicker._curInst.dpDiv.stop( true, true );
			if ( inst && $.datepicker._datepickerShowing ) {
				$.datepicker._hideDatepicker( $.datepicker._curInst.input[ 0 ] );
			}
		}

		beforeShow = $.datepicker._get( inst, "beforeShow" );
		beforeShowSettings = beforeShow ? beforeShow.apply( input, [ input, inst ] ) : {};
		if ( beforeShowSettings === false ) {
			return;
		}
		datepicker_extendRemove( inst.settings, beforeShowSettings );

		inst.lastVal = null;
		$.datepicker._lastInput = input;
		$.datepicker._setDateFromField( inst );

		if ( $.datepicker._inDialog ) { // hide cursor
			input.value = "";
		}
		if ( !$.datepicker._pos ) { // position below input
			$.datepicker._pos = $.datepicker._findPos( input );
			$.datepicker._pos[ 1 ] += input.offsetHeight; // add the height
		}

		isFixed = false;
		$( input ).parents().each( function() {
			isFixed |= $( this ).css( "position" ) === "fixed";
			return !isFixed;
		} );

		offset = { left: $.datepicker._pos[ 0 ], top: $.datepicker._pos[ 1 ] };
		$.datepicker._pos = null;

		//to avoid flashes on Firefox
		inst.dpDiv.empty();

		// determine sizing offscreen
		inst.dpDiv.css( { position: "absolute", display: "block", top: "-1000px" } );
		$.datepicker._updateDatepicker( inst );

		// fix width for dynamic number of date pickers
		// and adjust position before showing
		offset = $.datepicker._checkOffset( inst, offset, isFixed );
		inst.dpDiv.css( { position: ( $.datepicker._inDialog && $.blockUI ?
			"static" : ( isFixed ? "fixed" : "absolute" ) ), display: "none",
			left: offset.left + "px", top: offset.top + "px" } );

		if ( !inst.inline ) {
			showAnim = $.datepicker._get( inst, "showAnim" );
			duration = $.datepicker._get( inst, "duration" );
			inst.dpDiv.css( "z-index", datepicker_getZindex( $( input ) ) + 1 );
			$.datepicker._datepickerShowing = true;

			if ( $.effects && $.effects.effect[ showAnim ] ) {
				inst.dpDiv.show( showAnim, $.datepicker._get( inst, "showOptions" ), duration );
			} else {
				inst.dpDiv[ showAnim || "show" ]( showAnim ? duration : null );
			}

			if ( $.datepicker._shouldFocusInput( inst ) ) {
				inst.input.trigger( "focus" );
			}

			$.datepicker._curInst = inst;
		}
	},

	/* Generate the date picker content. */
	_updateDatepicker: function( inst ) {
		this.maxRows = 4; //Reset the max number of rows being displayed (see #7043)
		datepicker_instActive = inst; // for delegate hover events
		inst.dpDiv.empty().append( this._generateHTML( inst ) );
		this._attachHandlers( inst );

		var origyearshtml,
			numMonths = this._getNumberOfMonths( inst ),
			cols = numMonths[ 1 ],
			width = 17,
			activeCell = inst.dpDiv.find( "." + this._dayOverClass + " a" );

		if ( activeCell.length > 0 ) {
			datepicker_handleMouseover.apply( activeCell.get( 0 ) );
		}

		inst.dpDiv.removeClass( "ui-datepicker-multi-2 ui-datepicker-multi-3 ui-datepicker-multi-4" ).width( "" );
		if ( cols > 1 ) {
			inst.dpDiv.addClass( "ui-datepicker-multi-" + cols ).css( "width", ( width * cols ) + "em" );
		}
		inst.dpDiv[ ( numMonths[ 0 ] !== 1 || numMonths[ 1 ] !== 1 ? "add" : "remove" ) +
			"Class" ]( "ui-datepicker-multi" );
		inst.dpDiv[ ( this._get( inst, "isRTL" ) ? "add" : "remove" ) +
			"Class" ]( "ui-datepicker-rtl" );

		if ( inst === $.datepicker._curInst && $.datepicker._datepickerShowing && $.datepicker._shouldFocusInput( inst ) ) {
			inst.input.trigger( "focus" );
		}

		// Deffered render of the years select (to avoid flashes on Firefox)
		if ( inst.yearshtml ) {
			origyearshtml = inst.yearshtml;
			setTimeout( function() {

				//assure that inst.yearshtml didn't change.
				if ( origyearshtml === inst.yearshtml && inst.yearshtml ) {
					inst.dpDiv.find( "select.ui-datepicker-year:first" ).replaceWith( inst.yearshtml );
				}
				origyearshtml = inst.yearshtml = null;
			}, 0 );
		}
	},

	// #6694 - don't focus the input if it's already focused
	// this breaks the change event in IE
	// Support: IE and jQuery <1.9
	_shouldFocusInput: function( inst ) {
		return inst.input && inst.input.is( ":visible" ) && !inst.input.is( ":disabled" ) && !inst.input.is( ":focus" );
	},

	/* Check positioning to remain on screen. */
	_checkOffset: function( inst, offset, isFixed ) {
		var dpWidth = inst.dpDiv.outerWidth(),
			dpHeight = inst.dpDiv.outerHeight(),
			inputWidth = inst.input ? inst.input.outerWidth() : 0,
			inputHeight = inst.input ? inst.input.outerHeight() : 0,
			viewWidth = document.documentElement.clientWidth + ( isFixed ? 0 : $( document ).scrollLeft() ),
			viewHeight = document.documentElement.clientHeight + ( isFixed ? 0 : $( document ).scrollTop() );

		offset.left -= ( this._get( inst, "isRTL" ) ? ( dpWidth - inputWidth ) : 0 );
		offset.left -= ( isFixed && offset.left === inst.input.offset().left ) ? $( document ).scrollLeft() : 0;
		offset.top -= ( isFixed && offset.top === ( inst.input.offset().top + inputHeight ) ) ? $( document ).scrollTop() : 0;

		// Now check if datepicker is showing outside window viewport - move to a better place if so.
		offset.left -= Math.min( offset.left, ( offset.left + dpWidth > viewWidth && viewWidth > dpWidth ) ?
			Math.abs( offset.left + dpWidth - viewWidth ) : 0 );
		offset.top -= Math.min( offset.top, ( offset.top + dpHeight > viewHeight && viewHeight > dpHeight ) ?
			Math.abs( dpHeight + inputHeight ) : 0 );

		return offset;
	},

	/* Find an object's position on the screen. */
	_findPos: function( obj ) {
		var position,
			inst = this._getInst( obj ),
			isRTL = this._get( inst, "isRTL" );

		while ( obj && ( obj.type === "hidden" || obj.nodeType !== 1 || $.expr.filters.hidden( obj ) ) ) {
			obj = obj[ isRTL ? "previousSibling" : "nextSibling" ];
		}

		position = $( obj ).offset();
		return [ position.left, position.top ];
	},

	/* Hide the date picker from view.
	 * @param  input  element - the input field attached to the date picker
	 */
	_hideDatepicker: function( input ) {
		var showAnim, duration, postProcess, onClose,
			inst = this._curInst;

		if ( !inst || ( input && inst !== $.data( input, "datepicker" ) ) ) {
			return;
		}

		if ( this._datepickerShowing ) {
			showAnim = this._get( inst, "showAnim" );
			duration = this._get( inst, "duration" );
			postProcess = function() {
				$.datepicker._tidyDialog( inst );
			};

			// DEPRECATED: after BC for 1.8.x $.effects[ showAnim ] is not needed
			if ( $.effects && ( $.effects.effect[ showAnim ] || $.effects[ showAnim ] ) ) {
				inst.dpDiv.hide( showAnim, $.datepicker._get( inst, "showOptions" ), duration, postProcess );
			} else {
				inst.dpDiv[ ( showAnim === "slideDown" ? "slideUp" :
					( showAnim === "fadeIn" ? "fadeOut" : "hide" ) ) ]( ( showAnim ? duration : null ), postProcess );
			}

			if ( !showAnim ) {
				postProcess();
			}
			this._datepickerShowing = false;

			onClose = this._get( inst, "onClose" );
			if ( onClose ) {
				onClose.apply( ( inst.input ? inst.input[ 0 ] : null ), [ ( inst.input ? inst.input.val() : "" ), inst ] );
			}

			this._lastInput = null;
			if ( this._inDialog ) {
				this._dialogInput.css( { position: "absolute", left: "0", top: "-100px" } );
				if ( $.blockUI ) {
					$.unblockUI();
					$( "body" ).append( this.dpDiv );
				}
			}
			this._inDialog = false;
		}
	},

	/* Tidy up after a dialog display. */
	_tidyDialog: function( inst ) {
		inst.dpDiv.removeClass( this._dialogClass ).off( ".ui-datepicker-calendar" );
	},

	/* Close date picker if clicked elsewhere. */
	_checkExternalClick: function( event ) {
		if ( !$.datepicker._curInst ) {
			return;
		}

		var $target = $( event.target ),
			inst = $.datepicker._getInst( $target[ 0 ] );

		if ( ( ( $target[ 0 ].id !== $.datepicker._mainDivId &&
				$target.parents( "#" + $.datepicker._mainDivId ).length === 0 &&
				!$target.hasClass( $.datepicker.markerClassName ) &&
				!$target.closest( "." + $.datepicker._triggerClass ).length &&
				$.datepicker._datepickerShowing && !( $.datepicker._inDialog && $.blockUI ) ) ) ||
			( $target.hasClass( $.datepicker.markerClassName ) && $.datepicker._curInst !== inst ) ) {
				$.datepicker._hideDatepicker();
		}
	},

	/* Adjust one of the date sub-fields. */
	_adjustDate: function( id, offset, period ) {
		var target = $( id ),
			inst = this._getInst( target[ 0 ] );

		if ( this._isDisabledDatepicker( target[ 0 ] ) ) {
			return;
		}
		this._adjustInstDate( inst, offset +
			( period === "M" ? this._get( inst, "showCurrentAtPos" ) : 0 ), // undo positioning
			period );
		this._updateDatepicker( inst );
	},

	/* Action for current link. */
	_gotoToday: function( id ) {
		var date,
			target = $( id ),
			inst = this._getInst( target[ 0 ] );

		if ( this._get( inst, "gotoCurrent" ) && inst.currentDay ) {
			inst.selectedDay = inst.currentDay;
			inst.drawMonth = inst.selectedMonth = inst.currentMonth;
			inst.drawYear = inst.selectedYear = inst.currentYear;
		} else {
			date = new Date();
			inst.selectedDay = date.getDate();
			inst.drawMonth = inst.selectedMonth = date.getMonth();
			inst.drawYear = inst.selectedYear = date.getFullYear();
		}
		this._notifyChange( inst );
		this._adjustDate( target );
	},

	/* Action for selecting a new month/year. */
	_selectMonthYear: function( id, select, period ) {
		var target = $( id ),
			inst = this._getInst( target[ 0 ] );

		inst[ "selected" + ( period === "M" ? "Month" : "Year" ) ] =
		inst[ "draw" + ( period === "M" ? "Month" : "Year" ) ] =
			parseInt( select.options[ select.selectedIndex ].value, 10 );

		this._notifyChange( inst );
		this._adjustDate( target );
	},

	/* Action for selecting a day. */
	_selectDay: function( id, month, year, td ) {
		var inst,
			target = $( id );

		if ( $( td ).hasClass( this._unselectableClass ) || this._isDisabledDatepicker( target[ 0 ] ) ) {
			return;
		}

		inst = this._getInst( target[ 0 ] );
		inst.selectedDay = inst.currentDay = $( "a", td ).html();
		inst.selectedMonth = inst.currentMonth = month;
		inst.selectedYear = inst.currentYear = year;
		this._selectDate( id, this._formatDate( inst,
			inst.currentDay, inst.currentMonth, inst.currentYear ) );
	},

	/* Erase the input field and hide the date picker. */
	_clearDate: function( id ) {
		var target = $( id );
		this._selectDate( target, "" );
	},

	/* Update the input field with the selected date. */
	_selectDate: function( id, dateStr ) {
		var onSelect,
			target = $( id ),
			inst = this._getInst( target[ 0 ] );

		dateStr = ( dateStr != null ? dateStr : this._formatDate( inst ) );
		if ( inst.input ) {
			inst.input.val( dateStr );
		}
		this._updateAlternate( inst );

		onSelect = this._get( inst, "onSelect" );
		if ( onSelect ) {
			onSelect.apply( ( inst.input ? inst.input[ 0 ] : null ), [ dateStr, inst ] );  // trigger custom callback
		} else if ( inst.input ) {
			inst.input.trigger( "change" ); // fire the change event
		}

		if ( inst.inline ) {
			this._updateDatepicker( inst );
		} else {
			this._hideDatepicker();
			this._lastInput = inst.input[ 0 ];
			if ( typeof( inst.input[ 0 ] ) !== "object" ) {
				inst.input.trigger( "focus" ); // restore focus
			}
			this._lastInput = null;
		}
	},

	/* Update any alternate field to synchronise with the main field. */
	_updateAlternate: function( inst ) {
		var altFormat, date, dateStr,
			altField = this._get( inst, "altField" );

		if ( altField ) { // update alternate field too
			altFormat = this._get( inst, "altFormat" ) || this._get( inst, "dateFormat" );
			date = this._getDate( inst );
			dateStr = this.formatDate( altFormat, date, this._getFormatConfig( inst ) );
			$( altField ).val( dateStr );
		}
	},

	/* Set as beforeShowDay function to prevent selection of weekends.
	 * @param  date  Date - the date to customise
	 * @return [boolean, string] - is this date selectable?, what is its CSS class?
	 */
	noWeekends: function( date ) {
		var day = date.getDay();
		return [ ( day > 0 && day < 6 ), "" ];
	},

	/* Set as calculateWeek to determine the week of the year based on the ISO 8601 definition.
	 * @param  date  Date - the date to get the week for
	 * @return  number - the number of the week within the year that contains this date
	 */
	iso8601Week: function( date ) {
		var time,
			checkDate = new Date( date.getTime() );

		// Find Thursday of this week starting on Monday
		checkDate.setDate( checkDate.getDate() + 4 - ( checkDate.getDay() || 7 ) );

		time = checkDate.getTime();
		checkDate.setMonth( 0 ); // Compare with Jan 1
		checkDate.setDate( 1 );
		return Math.floor( Math.round( ( time - checkDate ) / 86400000 ) / 7 ) + 1;
	},

	/* Parse a string value into a date object.
	 * See formatDate below for the possible formats.
	 *
	 * @param  format string - the expected format of the date
	 * @param  value string - the date in the above format
	 * @param  settings Object - attributes include:
	 *					shortYearCutoff  number - the cutoff year for determining the century (optional)
	 *					dayNamesShort	string[7] - abbreviated names of the days from Sunday (optional)
	 *					dayNames		string[7] - names of the days from Sunday (optional)
	 *					monthNamesShort string[12] - abbreviated names of the months (optional)
	 *					monthNames		string[12] - names of the months (optional)
	 * @return  Date - the extracted date value or null if value is blank
	 */
	parseDate: function( format, value, settings ) {
		if ( format == null || value == null ) {
			throw "Invalid arguments";
		}

		value = ( typeof value === "object" ? value.toString() : value + "" );
		if ( value === "" ) {
			return null;
		}

		var iFormat, dim, extra,
			iValue = 0,
			shortYearCutoffTemp = ( settings ? settings.shortYearCutoff : null ) || this._defaults.shortYearCutoff,
			shortYearCutoff = ( typeof shortYearCutoffTemp !== "string" ? shortYearCutoffTemp :
				new Date().getFullYear() % 100 + parseInt( shortYearCutoffTemp, 10 ) ),
			dayNamesShort = ( settings ? settings.dayNamesShort : null ) || this._defaults.dayNamesShort,
			dayNames = ( settings ? settings.dayNames : null ) || this._defaults.dayNames,
			monthNamesShort = ( settings ? settings.monthNamesShort : null ) || this._defaults.monthNamesShort,
			monthNames = ( settings ? settings.monthNames : null ) || this._defaults.monthNames,
			year = -1,
			month = -1,
			day = -1,
			doy = -1,
			literal = false,
			date,

			// Check whether a format character is doubled
			lookAhead = function( match ) {
				var matches = ( iFormat + 1 < format.length && format.charAt( iFormat + 1 ) === match );
				if ( matches ) {
					iFormat++;
				}
				return matches;
			},

			// Extract a number from the string value
			getNumber = function( match ) {
				var isDoubled = lookAhead( match ),
					size = ( match === "@" ? 14 : ( match === "!" ? 20 :
					( match === "y" && isDoubled ? 4 : ( match === "o" ? 3 : 2 ) ) ) ),
					minSize = ( match === "y" ? size : 1 ),
					digits = new RegExp( "^\\d{" + minSize + "," + size + "}" ),
					num = value.substring( iValue ).match( digits );
				if ( !num ) {
					throw "Missing number at position " + iValue;
				}
				iValue += num[ 0 ].length;
				return parseInt( num[ 0 ], 10 );
			},

			// Extract a name from the string value and convert to an index
			getName = function( match, shortNames, longNames ) {
				var index = -1,
					names = $.map( lookAhead( match ) ? longNames : shortNames, function( v, k ) {
						return [ [ k, v ] ];
					} ).sort( function( a, b ) {
						return -( a[ 1 ].length - b[ 1 ].length );
					} );

				$.each( names, function( i, pair ) {
					var name = pair[ 1 ];
					if ( value.substr( iValue, name.length ).toLowerCase() === name.toLowerCase() ) {
						index = pair[ 0 ];
						iValue += name.length;
						return false;
					}
				} );
				if ( index !== -1 ) {
					return index + 1;
				} else {
					throw "Unknown name at position " + iValue;
				}
			},

			// Confirm that a literal character matches the string value
			checkLiteral = function() {
				if ( value.charAt( iValue ) !== format.charAt( iFormat ) ) {
					throw "Unexpected literal at position " + iValue;
				}
				iValue++;
			};

		for ( iFormat = 0; iFormat < format.length; iFormat++ ) {
			if ( literal ) {
				if ( format.charAt( iFormat ) === "'" && !lookAhead( "'" ) ) {
					literal = false;
				} else {
					checkLiteral();
				}
			} else {
				switch ( format.charAt( iFormat ) ) {
					case "d":
						day = getNumber( "d" );
						break;
					case "D":
						getName( "D", dayNamesShort, dayNames );
						break;
					case "o":
						doy = getNumber( "o" );
						break;
					case "m":
						month = getNumber( "m" );
						break;
					case "M":
						month = getName( "M", monthNamesShort, monthNames );
						break;
					case "y":
						year = getNumber( "y" );
						break;
					case "@":
						date = new Date( getNumber( "@" ) );
						year = date.getFullYear();
						month = date.getMonth() + 1;
						day = date.getDate();
						break;
					case "!":
						date = new Date( ( getNumber( "!" ) - this._ticksTo1970 ) / 10000 );
						year = date.getFullYear();
						month = date.getMonth() + 1;
						day = date.getDate();
						break;
					case "'":
						if ( lookAhead( "'" ) ) {
							checkLiteral();
						} else {
							literal = true;
						}
						break;
					default:
						checkLiteral();
				}
			}
		}

		if ( iValue < value.length ) {
			extra = value.substr( iValue );
			if ( !/^\s+/.test( extra ) ) {
				throw "Extra/unparsed characters found in date: " + extra;
			}
		}

		if ( year === -1 ) {
			year = new Date().getFullYear();
		} else if ( year < 100 ) {
			year += new Date().getFullYear() - new Date().getFullYear() % 100 +
				( year <= shortYearCutoff ? 0 : -100 );
		}

		if ( doy > -1 ) {
			month = 1;
			day = doy;
			do {
				dim = this._getDaysInMonth( year, month - 1 );
				if ( day <= dim ) {
					break;
				}
				month++;
				day -= dim;
			} while ( true );
		}

		date = this._daylightSavingAdjust( new Date( year, month - 1, day ) );
		if ( date.getFullYear() !== year || date.getMonth() + 1 !== month || date.getDate() !== day ) {
			throw "Invalid date"; // E.g. 31/02/00
		}
		return date;
	},

	/* Standard date formats. */
	ATOM: "yy-mm-dd", // RFC 3339 (ISO 8601)
	COOKIE: "D, dd M yy",
	ISO_8601: "yy-mm-dd",
	RFC_822: "D, d M y",
	RFC_850: "DD, dd-M-y",
	RFC_1036: "D, d M y",
	RFC_1123: "D, d M yy",
	RFC_2822: "D, d M yy",
	RSS: "D, d M y", // RFC 822
	TICKS: "!",
	TIMESTAMP: "@",
	W3C: "yy-mm-dd", // ISO 8601

	_ticksTo1970: ( ( ( 1970 - 1 ) * 365 + Math.floor( 1970 / 4 ) - Math.floor( 1970 / 100 ) +
		Math.floor( 1970 / 400 ) ) * 24 * 60 * 60 * 10000000 ),

	/* Format a date object into a string value.
	 * The format can be combinations of the following:
	 * d  - day of month (no leading zero)
	 * dd - day of month (two digit)
	 * o  - day of year (no leading zeros)
	 * oo - day of year (three digit)
	 * D  - day name short
	 * DD - day name long
	 * m  - month of year (no leading zero)
	 * mm - month of year (two digit)
	 * M  - month name short
	 * MM - month name long
	 * y  - year (two digit)
	 * yy - year (four digit)
	 * @ - Unix timestamp (ms since 01/01/1970)
	 * ! - Windows ticks (100ns since 01/01/0001)
	 * "..." - literal text
	 * '' - single quote
	 *
	 * @param  format string - the desired format of the date
	 * @param  date Date - the date value to format
	 * @param  settings Object - attributes include:
	 *					dayNamesShort	string[7] - abbreviated names of the days from Sunday (optional)
	 *					dayNames		string[7] - names of the days from Sunday (optional)
	 *					monthNamesShort string[12] - abbreviated names of the months (optional)
	 *					monthNames		string[12] - names of the months (optional)
	 * @return  string - the date in the above format
	 */
	formatDate: function( format, date, settings ) {
		if ( !date ) {
			return "";
		}

		var iFormat,
			dayNamesShort = ( settings ? settings.dayNamesShort : null ) || this._defaults.dayNamesShort,
			dayNames = ( settings ? settings.dayNames : null ) || this._defaults.dayNames,
			monthNamesShort = ( settings ? settings.monthNamesShort : null ) || this._defaults.monthNamesShort,
			monthNames = ( settings ? settings.monthNames : null ) || this._defaults.monthNames,

			// Check whether a format character is doubled
			lookAhead = function( match ) {
				var matches = ( iFormat + 1 < format.length && format.charAt( iFormat + 1 ) === match );
				if ( matches ) {
					iFormat++;
				}
				return matches;
			},

			// Format a number, with leading zero if necessary
			formatNumber = function( match, value, len ) {
				var num = "" + value;
				if ( lookAhead( match ) ) {
					while ( num.length < len ) {
						num = "0" + num;
					}
				}
				return num;
			},

			// Format a name, short or long as requested
			formatName = function( match, value, shortNames, longNames ) {
				return ( lookAhead( match ) ? longNames[ value ] : shortNames[ value ] );
			},
			output = "",
			literal = false;

		if ( date ) {
			for ( iFormat = 0; iFormat < format.length; iFormat++ ) {
				if ( literal ) {
					if ( format.charAt( iFormat ) === "'" && !lookAhead( "'" ) ) {
						literal = false;
					} else {
						output += format.charAt( iFormat );
					}
				} else {
					switch ( format.charAt( iFormat ) ) {
						case "d":
							output += formatNumber( "d", date.getDate(), 2 );
							break;
						case "D":
							output += formatName( "D", date.getDay(), dayNamesShort, dayNames );
							break;
						case "o":
							output += formatNumber( "o",
								Math.round( ( new Date( date.getFullYear(), date.getMonth(), date.getDate() ).getTime() - new Date( date.getFullYear(), 0, 0 ).getTime() ) / 86400000 ), 3 );
							break;
						case "m":
							output += formatNumber( "m", date.getMonth() + 1, 2 );
							break;
						case "M":
							output += formatName( "M", date.getMonth(), monthNamesShort, monthNames );
							break;
						case "y":
							output += ( lookAhead( "y" ) ? date.getFullYear() :
								( date.getFullYear() % 100 < 10 ? "0" : "" ) + date.getFullYear() % 100 );
							break;
						case "@":
							output += date.getTime();
							break;
						case "!":
							output += date.getTime() * 10000 + this._ticksTo1970;
							break;
						case "'":
							if ( lookAhead( "'" ) ) {
								output += "'";
							} else {
								literal = true;
							}
							break;
						default:
							output += format.charAt( iFormat );
					}
				}
			}
		}
		return output;
	},

	/* Extract all possible characters from the date format. */
	_possibleChars: function( format ) {
		var iFormat,
			chars = "",
			literal = false,

			// Check whether a format character is doubled
			lookAhead = function( match ) {
				var matches = ( iFormat + 1 < format.length && format.charAt( iFormat + 1 ) === match );
				if ( matches ) {
					iFormat++;
				}
				return matches;
			};

		for ( iFormat = 0; iFormat < format.length; iFormat++ ) {
			if ( literal ) {
				if ( format.charAt( iFormat ) === "'" && !lookAhead( "'" ) ) {
					literal = false;
				} else {
					chars += format.charAt( iFormat );
				}
			} else {
				switch ( format.charAt( iFormat ) ) {
					case "d": case "m": case "y": case "@":
						chars += "0123456789";
						break;
					case "D": case "M":
						return null; // Accept anything
					case "'":
						if ( lookAhead( "'" ) ) {
							chars += "'";
						} else {
							literal = true;
						}
						break;
					default:
						chars += format.charAt( iFormat );
				}
			}
		}
		return chars;
	},

	/* Get a setting value, defaulting if necessary. */
	_get: function( inst, name ) {
		return inst.settings[ name ] !== undefined ?
			inst.settings[ name ] : this._defaults[ name ];
	},

	/* Parse existing date and initialise date picker. */
	_setDateFromField: function( inst, noDefault ) {
		if ( inst.input.val() === inst.lastVal ) {
			return;
		}

		var dateFormat = this._get( inst, "dateFormat" ),
			dates = inst.lastVal = inst.input ? inst.input.val() : null,
			defaultDate = this._getDefaultDate( inst ),
			date = defaultDate,
			settings = this._getFormatConfig( inst );

		try {
			date = this.parseDate( dateFormat, dates, settings ) || defaultDate;
		} catch ( event ) {
			dates = ( noDefault ? "" : dates );
		}
		inst.selectedDay = date.getDate();
		inst.drawMonth = inst.selectedMonth = date.getMonth();
		inst.drawYear = inst.selectedYear = date.getFullYear();
		inst.currentDay = ( dates ? date.getDate() : 0 );
		inst.currentMonth = ( dates ? date.getMonth() : 0 );
		inst.currentYear = ( dates ? date.getFullYear() : 0 );
		this._adjustInstDate( inst );
	},

	/* Retrieve the default date shown on opening. */
	_getDefaultDate: function( inst ) {
		return this._restrictMinMax( inst,
			this._determineDate( inst, this._get( inst, "defaultDate" ), new Date() ) );
	},

	/* A date may be specified as an exact value or a relative one. */
	_determineDate: function( inst, date, defaultDate ) {
		var offsetNumeric = function( offset ) {
				var date = new Date();
				date.setDate( date.getDate() + offset );
				return date;
			},
			offsetString = function( offset ) {
				try {
					return $.datepicker.parseDate( $.datepicker._get( inst, "dateFormat" ),
						offset, $.datepicker._getFormatConfig( inst ) );
				}
				catch ( e ) {

					// Ignore
				}

				var date = ( offset.toLowerCase().match( /^c/ ) ?
					$.datepicker._getDate( inst ) : null ) || new Date(),
					year = date.getFullYear(),
					month = date.getMonth(),
					day = date.getDate(),
					pattern = /([+\-]?[0-9]+)\s*(d|D|w|W|m|M|y|Y)?/g,
					matches = pattern.exec( offset );

				while ( matches ) {
					switch ( matches[ 2 ] || "d" ) {
						case "d" : case "D" :
							day += parseInt( matches[ 1 ], 10 ); break;
						case "w" : case "W" :
							day += parseInt( matches[ 1 ], 10 ) * 7; break;
						case "m" : case "M" :
							month += parseInt( matches[ 1 ], 10 );
							day = Math.min( day, $.datepicker._getDaysInMonth( year, month ) );
							break;
						case "y": case "Y" :
							year += parseInt( matches[ 1 ], 10 );
							day = Math.min( day, $.datepicker._getDaysInMonth( year, month ) );
							break;
					}
					matches = pattern.exec( offset );
				}
				return new Date( year, month, day );
			},
			newDate = ( date == null || date === "" ? defaultDate : ( typeof date === "string" ? offsetString( date ) :
				( typeof date === "number" ? ( isNaN( date ) ? defaultDate : offsetNumeric( date ) ) : new Date( date.getTime() ) ) ) );

		newDate = ( newDate && newDate.toString() === "Invalid Date" ? defaultDate : newDate );
		if ( newDate ) {
			newDate.setHours( 0 );
			newDate.setMinutes( 0 );
			newDate.setSeconds( 0 );
			newDate.setMilliseconds( 0 );
		}
		return this._daylightSavingAdjust( newDate );
	},

	/* Handle switch to/from daylight saving.
	 * Hours may be non-zero on daylight saving cut-over:
	 * > 12 when midnight changeover, but then cannot generate
	 * midnight datetime, so jump to 1AM, otherwise reset.
	 * @param  date  (Date) the date to check
	 * @return  (Date) the corrected date
	 */
	_daylightSavingAdjust: function( date ) {
		if ( !date ) {
			return null;
		}
		date.setHours( date.getHours() > 12 ? date.getHours() + 2 : 0 );
		return date;
	},

	/* Set the date(s) directly. */
	_setDate: function( inst, date, noChange ) {
		var clear = !date,
			origMonth = inst.selectedMonth,
			origYear = inst.selectedYear,
			newDate = this._restrictMinMax( inst, this._determineDate( inst, date, new Date() ) );

		inst.selectedDay = inst.currentDay = newDate.getDate();
		inst.drawMonth = inst.selectedMonth = inst.currentMonth = newDate.getMonth();
		inst.drawYear = inst.selectedYear = inst.currentYear = newDate.getFullYear();
		if ( ( origMonth !== inst.selectedMonth || origYear !== inst.selectedYear ) && !noChange ) {
			this._notifyChange( inst );
		}
		this._adjustInstDate( inst );
		if ( inst.input ) {
			inst.input.val( clear ? "" : this._formatDate( inst ) );
		}
	},

	/* Retrieve the date(s) directly. */
	_getDate: function( inst ) {
		var startDate = ( !inst.currentYear || ( inst.input && inst.input.val() === "" ) ? null :
			this._daylightSavingAdjust( new Date(
			inst.currentYear, inst.currentMonth, inst.currentDay ) ) );
			return startDate;
	},

	/* Attach the onxxx handlers.  These are declared statically so
	 * they work with static code transformers like Caja.
	 */
	_attachHandlers: function( inst ) {
		var stepMonths = this._get( inst, "stepMonths" ),
			id = "#" + inst.id.replace( /\\\\/g, "\\" );
		inst.dpDiv.find( "[data-handler]" ).map( function() {
			var handler = {
				prev: function() {
					$.datepicker._adjustDate( id, -stepMonths, "M" );
				},
				next: function() {
					$.datepicker._adjustDate( id, +stepMonths, "M" );
				},
				hide: function() {
					$.datepicker._hideDatepicker();
				},
				today: function() {
					$.datepicker._gotoToday( id );
				},
				selectDay: function() {
					$.datepicker._selectDay( id, +this.getAttribute( "data-month" ), +this.getAttribute( "data-year" ), this );
					return false;
				},
				selectMonth: function() {
					$.datepicker._selectMonthYear( id, this, "M" );
					return false;
				},
				selectYear: function() {
					$.datepicker._selectMonthYear( id, this, "Y" );
					return false;
				}
			};
			$( this ).on( this.getAttribute( "data-event" ), handler[ this.getAttribute( "data-handler" ) ] );
		} );
	},

	/* Generate the HTML for the current state of the date picker. */
	_generateHTML: function( inst ) {
		var maxDraw, prevText, prev, nextText, next, currentText, gotoDate,
			controls, buttonPanel, firstDay, showWeek, dayNames, dayNamesMin,
			monthNames, monthNamesShort, beforeShowDay, showOtherMonths,
			selectOtherMonths, defaultDate, html, dow, row, group, col, selectedDate,
			cornerClass, calender, thead, day, daysInMonth, leadDays, curRows, numRows,
			printDate, dRow, tbody, daySettings, otherMonth, unselectable,
			tempDate = new Date(),
			today = this._daylightSavingAdjust(
				new Date( tempDate.getFullYear(), tempDate.getMonth(), tempDate.getDate() ) ), // clear time
			isRTL = this._get( inst, "isRTL" ),
			showButtonPanel = this._get( inst, "showButtonPanel" ),
			hideIfNoPrevNext = this._get( inst, "hideIfNoPrevNext" ),
			navigationAsDateFormat = this._get( inst, "navigationAsDateFormat" ),
			numMonths = this._getNumberOfMonths( inst ),
			showCurrentAtPos = this._get( inst, "showCurrentAtPos" ),
			stepMonths = this._get( inst, "stepMonths" ),
			isMultiMonth = ( numMonths[ 0 ] !== 1 || numMonths[ 1 ] !== 1 ),
			currentDate = this._daylightSavingAdjust( ( !inst.currentDay ? new Date( 9999, 9, 9 ) :
				new Date( inst.currentYear, inst.currentMonth, inst.currentDay ) ) ),
			minDate = this._getMinMaxDate( inst, "min" ),
			maxDate = this._getMinMaxDate( inst, "max" ),
			drawMonth = inst.drawMonth - showCurrentAtPos,
			drawYear = inst.drawYear;

		if ( drawMonth < 0 ) {
			drawMonth += 12;
			drawYear--;
		}
		if ( maxDate ) {
			maxDraw = this._daylightSavingAdjust( new Date( maxDate.getFullYear(),
				maxDate.getMonth() - ( numMonths[ 0 ] * numMonths[ 1 ] ) + 1, maxDate.getDate() ) );
			maxDraw = ( minDate && maxDraw < minDate ? minDate : maxDraw );
			while ( this._daylightSavingAdjust( new Date( drawYear, drawMonth, 1 ) ) > maxDraw ) {
				drawMonth--;
				if ( drawMonth < 0 ) {
					drawMonth = 11;
					drawYear--;
				}
			}
		}
		inst.drawMonth = drawMonth;
		inst.drawYear = drawYear;

		prevText = this._get( inst, "prevText" );
		prevText = ( !navigationAsDateFormat ? prevText : this.formatDate( prevText,
			this._daylightSavingAdjust( new Date( drawYear, drawMonth - stepMonths, 1 ) ),
			this._getFormatConfig( inst ) ) );

		prev = ( this._canAdjustMonth( inst, -1, drawYear, drawMonth ) ?
			"<a class='ui-datepicker-prev ui-corner-all' data-handler='prev' data-event='click'" +
			" title='" + prevText + "'><span class='ui-icon ui-icon-circle-triangle-" + ( isRTL ? "e" : "w" ) + "'>" + prevText + "</span></a>" :
			( hideIfNoPrevNext ? "" : "<a class='ui-datepicker-prev ui-corner-all ui-state-disabled' title='" + prevText + "'><span class='ui-icon ui-icon-circle-triangle-" + ( isRTL ? "e" : "w" ) + "'>" + prevText + "</span></a>" ) );

		nextText = this._get( inst, "nextText" );
		nextText = ( !navigationAsDateFormat ? nextText : this.formatDate( nextText,
			this._daylightSavingAdjust( new Date( drawYear, drawMonth + stepMonths, 1 ) ),
			this._getFormatConfig( inst ) ) );

		next = ( this._canAdjustMonth( inst, +1, drawYear, drawMonth ) ?
			"<a class='ui-datepicker-next ui-corner-all' data-handler='next' data-event='click'" +
			" title='" + nextText + "'><span class='ui-icon ui-icon-circle-triangle-" + ( isRTL ? "w" : "e" ) + "'>" + nextText + "</span></a>" :
			( hideIfNoPrevNext ? "" : "<a class='ui-datepicker-next ui-corner-all ui-state-disabled' title='" + nextText + "'><span class='ui-icon ui-icon-circle-triangle-" + ( isRTL ? "w" : "e" ) + "'>" + nextText + "</span></a>" ) );

		currentText = this._get( inst, "currentText" );
		gotoDate = ( this._get( inst, "gotoCurrent" ) && inst.currentDay ? currentDate : today );
		currentText = ( !navigationAsDateFormat ? currentText :
			this.formatDate( currentText, gotoDate, this._getFormatConfig( inst ) ) );

		controls = ( !inst.inline ? "<button type='button' class='ui-datepicker-close ui-state-default ui-priority-primary ui-corner-all' data-handler='hide' data-event='click'>" +
			this._get( inst, "closeText" ) + "</button>" : "" );

		buttonPanel = ( showButtonPanel ) ? "<div class='ui-datepicker-buttonpane ui-widget-content'>" + ( isRTL ? controls : "" ) +
			( this._isInRange( inst, gotoDate ) ? "<button type='button' class='ui-datepicker-current ui-state-default ui-priority-secondary ui-corner-all' data-handler='today' data-event='click'" +
			">" + currentText + "</button>" : "" ) + ( isRTL ? "" : controls ) + "</div>" : "";

		firstDay = parseInt( this._get( inst, "firstDay" ), 10 );
		firstDay = ( isNaN( firstDay ) ? 0 : firstDay );

		showWeek = this._get( inst, "showWeek" );
		dayNames = this._get( inst, "dayNames" );
		dayNamesMin = this._get( inst, "dayNamesMin" );
		monthNames = this._get( inst, "monthNames" );
		monthNamesShort = this._get( inst, "monthNamesShort" );
		beforeShowDay = this._get( inst, "beforeShowDay" );
		showOtherMonths = this._get( inst, "showOtherMonths" );
		selectOtherMonths = this._get( inst, "selectOtherMonths" );
		defaultDate = this._getDefaultDate( inst );
		html = "";

		for ( row = 0; row < numMonths[ 0 ]; row++ ) {
			group = "";
			this.maxRows = 4;
			for ( col = 0; col < numMonths[ 1 ]; col++ ) {
				selectedDate = this._daylightSavingAdjust( new Date( drawYear, drawMonth, inst.selectedDay ) );
				cornerClass = " ui-corner-all";
				calender = "";
				if ( isMultiMonth ) {
					calender += "<div class='ui-datepicker-group";
					if ( numMonths[ 1 ] > 1 ) {
						switch ( col ) {
							case 0: calender += " ui-datepicker-group-first";
								cornerClass = " ui-corner-" + ( isRTL ? "right" : "left" ); break;
							case numMonths[ 1 ] - 1: calender += " ui-datepicker-group-last";
								cornerClass = " ui-corner-" + ( isRTL ? "left" : "right" ); break;
							default: calender += " ui-datepicker-group-middle"; cornerClass = ""; break;
						}
					}
					calender += "'>";
				}
				calender += "<div class='ui-datepicker-header ui-widget-header ui-helper-clearfix" + cornerClass + "'>" +
					( /all|left/.test( cornerClass ) && row === 0 ? ( isRTL ? next : prev ) : "" ) +
					( /all|right/.test( cornerClass ) && row === 0 ? ( isRTL ? prev : next ) : "" ) +
					this._generateMonthYearHeader( inst, drawMonth, drawYear, minDate, maxDate,
					row > 0 || col > 0, monthNames, monthNamesShort ) + // draw month headers
					"</div><table class='ui-datepicker-calendar'><thead>" +
					"<tr>";
				thead = ( showWeek ? "<th class='ui-datepicker-week-col'>" + this._get( inst, "weekHeader" ) + "</th>" : "" );
				for ( dow = 0; dow < 7; dow++ ) { // days of the week
					day = ( dow + firstDay ) % 7;
					thead += "<th scope='col'" + ( ( dow + firstDay + 6 ) % 7 >= 5 ? " class='ui-datepicker-week-end'" : "" ) + ">" +
						"<span title='" + dayNames[ day ] + "'>" + dayNamesMin[ day ] + "</span></th>";
				}
				calender += thead + "</tr></thead><tbody>";
				daysInMonth = this._getDaysInMonth( drawYear, drawMonth );
				if ( drawYear === inst.selectedYear && drawMonth === inst.selectedMonth ) {
					inst.selectedDay = Math.min( inst.selectedDay, daysInMonth );
				}
				leadDays = ( this._getFirstDayOfMonth( drawYear, drawMonth ) - firstDay + 7 ) % 7;
				curRows = Math.ceil( ( leadDays + daysInMonth ) / 7 ); // calculate the number of rows to generate
				numRows = ( isMultiMonth ? this.maxRows > curRows ? this.maxRows : curRows : curRows ); //If multiple months, use the higher number of rows (see #7043)
				this.maxRows = numRows;
				printDate = this._daylightSavingAdjust( new Date( drawYear, drawMonth, 1 - leadDays ) );
				for ( dRow = 0; dRow < numRows; dRow++ ) { // create date picker rows
					calender += "<tr>";
					tbody = ( !showWeek ? "" : "<td class='ui-datepicker-week-col'>" +
						this._get( inst, "calculateWeek" )( printDate ) + "</td>" );
					for ( dow = 0; dow < 7; dow++ ) { // create date picker days
						daySettings = ( beforeShowDay ?
							beforeShowDay.apply( ( inst.input ? inst.input[ 0 ] : null ), [ printDate ] ) : [ true, "" ] );
						otherMonth = ( printDate.getMonth() !== drawMonth );
						unselectable = ( otherMonth && !selectOtherMonths ) || !daySettings[ 0 ] ||
							( minDate && printDate < minDate ) || ( maxDate && printDate > maxDate );
						tbody += "<td class='" +
							( ( dow + firstDay + 6 ) % 7 >= 5 ? " ui-datepicker-week-end" : "" ) + // highlight weekends
							( otherMonth ? " ui-datepicker-other-month" : "" ) + // highlight days from other months
							( ( printDate.getTime() === selectedDate.getTime() && drawMonth === inst.selectedMonth && inst._keyEvent ) || // user pressed key
							( defaultDate.getTime() === printDate.getTime() && defaultDate.getTime() === selectedDate.getTime() ) ?

							// or defaultDate is current printedDate and defaultDate is selectedDate
							" " + this._dayOverClass : "" ) + // highlight selected day
							( unselectable ? " " + this._unselectableClass + " ui-state-disabled" : "" ) +  // highlight unselectable days
							( otherMonth && !showOtherMonths ? "" : " " + daySettings[ 1 ] + // highlight custom dates
							( printDate.getTime() === currentDate.getTime() ? " " + this._currentClass : "" ) + // highlight selected day
							( printDate.getTime() === today.getTime() ? " ui-datepicker-today" : "" ) ) + "'" + // highlight today (if different)
							( ( !otherMonth || showOtherMonths ) && daySettings[ 2 ] ? " title='" + daySettings[ 2 ].replace( /'/g, "&#39;" ) + "'" : "" ) + // cell title
							( unselectable ? "" : " data-handler='selectDay' data-event='click' data-month='" + printDate.getMonth() + "' data-year='" + printDate.getFullYear() + "'" ) + ">" + // actions
							( otherMonth && !showOtherMonths ? "&#xa0;" : // display for other months
							( unselectable ? "<span class='ui-state-default'>" + printDate.getDate() + "</span>" : "<a class='ui-state-default" +
							( printDate.getTime() === today.getTime() ? " ui-state-highlight" : "" ) +
							( printDate.getTime() === currentDate.getTime() ? " ui-state-active" : "" ) + // highlight selected day
							( otherMonth ? " ui-priority-secondary" : "" ) + // distinguish dates from other months
							"' href='#'>" + printDate.getDate() + "</a>" ) ) + "</td>"; // display selectable date
						printDate.setDate( printDate.getDate() + 1 );
						printDate = this._daylightSavingAdjust( printDate );
					}
					calender += tbody + "</tr>";
				}
				drawMonth++;
				if ( drawMonth > 11 ) {
					drawMonth = 0;
					drawYear++;
				}
				calender += "</tbody></table>" + ( isMultiMonth ? "</div>" +
							( ( numMonths[ 0 ] > 0 && col === numMonths[ 1 ] - 1 ) ? "<div class='ui-datepicker-row-break'></div>" : "" ) : "" );
				group += calender;
			}
			html += group;
		}
		html += buttonPanel;
		inst._keyEvent = false;
		return html;
	},

	/* Generate the month and year header. */
	_generateMonthYearHeader: function( inst, drawMonth, drawYear, minDate, maxDate,
			secondary, monthNames, monthNamesShort ) {

		var inMinYear, inMaxYear, month, years, thisYear, determineYear, year, endYear,
			changeMonth = this._get( inst, "changeMonth" ),
			changeYear = this._get( inst, "changeYear" ),
			showMonthAfterYear = this._get( inst, "showMonthAfterYear" ),
			html = "<div class='ui-datepicker-title'>",
			monthHtml = "";

		// Month selection
		if ( secondary || !changeMonth ) {
			monthHtml += "<span class='ui-datepicker-month'>" + monthNames[ drawMonth ] + "</span>";
		} else {
			inMinYear = ( minDate && minDate.getFullYear() === drawYear );
			inMaxYear = ( maxDate && maxDate.getFullYear() === drawYear );
			monthHtml += "<select class='ui-datepicker-month' data-handler='selectMonth' data-event='change'>";
			for ( month = 0; month < 12; month++ ) {
				if ( ( !inMinYear || month >= minDate.getMonth() ) && ( !inMaxYear || month <= maxDate.getMonth() ) ) {
					monthHtml += "<option value='" + month + "'" +
						( month === drawMonth ? " selected='selected'" : "" ) +
						">" + monthNamesShort[ month ] + "</option>";
				}
			}
			monthHtml += "</select>";
		}

		if ( !showMonthAfterYear ) {
			html += monthHtml + ( secondary || !( changeMonth && changeYear ) ? "&#xa0;" : "" );
		}

		// Year selection
		if ( !inst.yearshtml ) {
			inst.yearshtml = "";
			if ( secondary || !changeYear ) {
				html += "<span class='ui-datepicker-year'>" + drawYear + "</span>";
			} else {

				// determine range of years to display
				years = this._get( inst, "yearRange" ).split( ":" );
				thisYear = new Date().getFullYear();
				determineYear = function( value ) {
					var year = ( value.match( /c[+\-].*/ ) ? drawYear + parseInt( value.substring( 1 ), 10 ) :
						( value.match( /[+\-].*/ ) ? thisYear + parseInt( value, 10 ) :
						parseInt( value, 10 ) ) );
					return ( isNaN( year ) ? thisYear : year );
				};
				year = determineYear( years[ 0 ] );
				endYear = Math.max( year, determineYear( years[ 1 ] || "" ) );
				year = ( minDate ? Math.max( year, minDate.getFullYear() ) : year );
				endYear = ( maxDate ? Math.min( endYear, maxDate.getFullYear() ) : endYear );
				inst.yearshtml += "<select class='ui-datepicker-year' data-handler='selectYear' data-event='change'>";
				for ( ; year <= endYear; year++ ) {
					inst.yearshtml += "<option value='" + year + "'" +
						( year === drawYear ? " selected='selected'" : "" ) +
						">" + year + "</option>";
				}
				inst.yearshtml += "</select>";

				html += inst.yearshtml;
				inst.yearshtml = null;
			}
		}

		html += this._get( inst, "yearSuffix" );
		if ( showMonthAfterYear ) {
			html += ( secondary || !( changeMonth && changeYear ) ? "&#xa0;" : "" ) + monthHtml;
		}
		html += "</div>"; // Close datepicker_header
		return html;
	},

	/* Adjust one of the date sub-fields. */
	_adjustInstDate: function( inst, offset, period ) {
		var year = inst.selectedYear + ( period === "Y" ? offset : 0 ),
			month = inst.selectedMonth + ( period === "M" ? offset : 0 ),
			day = Math.min( inst.selectedDay, this._getDaysInMonth( year, month ) ) + ( period === "D" ? offset : 0 ),
			date = this._restrictMinMax( inst, this._daylightSavingAdjust( new Date( year, month, day ) ) );

		inst.selectedDay = date.getDate();
		inst.drawMonth = inst.selectedMonth = date.getMonth();
		inst.drawYear = inst.selectedYear = date.getFullYear();
		if ( period === "M" || period === "Y" ) {
			this._notifyChange( inst );
		}
	},

	/* Ensure a date is within any min/max bounds. */
	_restrictMinMax: function( inst, date ) {
		var minDate = this._getMinMaxDate( inst, "min" ),
			maxDate = this._getMinMaxDate( inst, "max" ),
			newDate = ( minDate && date < minDate ? minDate : date );
		return ( maxDate && newDate > maxDate ? maxDate : newDate );
	},

	/* Notify change of month/year. */
	_notifyChange: function( inst ) {
		var onChange = this._get( inst, "onChangeMonthYear" );
		if ( onChange ) {
			onChange.apply( ( inst.input ? inst.input[ 0 ] : null ),
				[ inst.selectedYear, inst.selectedMonth + 1, inst ] );
		}
	},

	/* Determine the number of months to show. */
	_getNumberOfMonths: function( inst ) {
		var numMonths = this._get( inst, "numberOfMonths" );
		return ( numMonths == null ? [ 1, 1 ] : ( typeof numMonths === "number" ? [ 1, numMonths ] : numMonths ) );
	},

	/* Determine the current maximum date - ensure no time components are set. */
	_getMinMaxDate: function( inst, minMax ) {
		return this._determineDate( inst, this._get( inst, minMax + "Date" ), null );
	},

	/* Find the number of days in a given month. */
	_getDaysInMonth: function( year, month ) {
		return 32 - this._daylightSavingAdjust( new Date( year, month, 32 ) ).getDate();
	},

	/* Find the day of the week of the first of a month. */
	_getFirstDayOfMonth: function( year, month ) {
		return new Date( year, month, 1 ).getDay();
	},

	/* Determines if we should allow a "next/prev" month display change. */
	_canAdjustMonth: function( inst, offset, curYear, curMonth ) {
		var numMonths = this._getNumberOfMonths( inst ),
			date = this._daylightSavingAdjust( new Date( curYear,
			curMonth + ( offset < 0 ? offset : numMonths[ 0 ] * numMonths[ 1 ] ), 1 ) );

		if ( offset < 0 ) {
			date.setDate( this._getDaysInMonth( date.getFullYear(), date.getMonth() ) );
		}
		return this._isInRange( inst, date );
	},

	/* Is the given date in the accepted range? */
	_isInRange: function( inst, date ) {
		var yearSplit, currentYear,
			minDate = this._getMinMaxDate( inst, "min" ),
			maxDate = this._getMinMaxDate( inst, "max" ),
			minYear = null,
			maxYear = null,
			years = this._get( inst, "yearRange" );
			if ( years ) {
				yearSplit = years.split( ":" );
				currentYear = new Date().getFullYear();
				minYear = parseInt( yearSplit[ 0 ], 10 );
				maxYear = parseInt( yearSplit[ 1 ], 10 );
				if ( yearSplit[ 0 ].match( /[+\-].*/ ) ) {
					minYear += currentYear;
				}
				if ( yearSplit[ 1 ].match( /[+\-].*/ ) ) {
					maxYear += currentYear;
				}
			}

		return ( ( !minDate || date.getTime() >= minDate.getTime() ) &&
			( !maxDate || date.getTime() <= maxDate.getTime() ) &&
			( !minYear || date.getFullYear() >= minYear ) &&
			( !maxYear || date.getFullYear() <= maxYear ) );
	},

	/* Provide the configuration settings for formatting/parsing. */
	_getFormatConfig: function( inst ) {
		var shortYearCutoff = this._get( inst, "shortYearCutoff" );
		shortYearCutoff = ( typeof shortYearCutoff !== "string" ? shortYearCutoff :
			new Date().getFullYear() % 100 + parseInt( shortYearCutoff, 10 ) );
		return { shortYearCutoff: shortYearCutoff,
			dayNamesShort: this._get( inst, "dayNamesShort" ), dayNames: this._get( inst, "dayNames" ),
			monthNamesShort: this._get( inst, "monthNamesShort" ), monthNames: this._get( inst, "monthNames" ) };
	},

	/* Format the given date for display. */
	_formatDate: function( inst, day, month, year ) {
		if ( !day ) {
			inst.currentDay = inst.selectedDay;
			inst.currentMonth = inst.selectedMonth;
			inst.currentYear = inst.selectedYear;
		}
		var date = ( day ? ( typeof day === "object" ? day :
			this._daylightSavingAdjust( new Date( year, month, day ) ) ) :
			this._daylightSavingAdjust( new Date( inst.currentYear, inst.currentMonth, inst.currentDay ) ) );
		return this.formatDate( this._get( inst, "dateFormat" ), date, this._getFormatConfig( inst ) );
	}
} );

/*
 * Bind hover events for datepicker elements.
 * Done via delegate so the binding only occurs once in the lifetime of the parent div.
 * Global datepicker_instActive, set by _updateDatepicker allows the handlers to find their way back to the active picker.
 */
function datepicker_bindHover( dpDiv ) {
	var selector = "button, .ui-datepicker-prev, .ui-datepicker-next, .ui-datepicker-calendar td a";
	return dpDiv.on( "mouseout", selector, function() {
			$( this ).removeClass( "ui-state-hover" );
			if ( this.className.indexOf( "ui-datepicker-prev" ) !== -1 ) {
				$( this ).removeClass( "ui-datepicker-prev-hover" );
			}
			if ( this.className.indexOf( "ui-datepicker-next" ) !== -1 ) {
				$( this ).removeClass( "ui-datepicker-next-hover" );
			}
		} )
		.on( "mouseover", selector, datepicker_handleMouseover );
}

function datepicker_handleMouseover() {
	if ( !$.datepicker._isDisabledDatepicker( datepicker_instActive.inline ? datepicker_instActive.dpDiv.parent()[ 0 ] : datepicker_instActive.input[ 0 ] ) ) {
		$( this ).parents( ".ui-datepicker-calendar" ).find( "a" ).removeClass( "ui-state-hover" );
		$( this ).addClass( "ui-state-hover" );
		if ( this.className.indexOf( "ui-datepicker-prev" ) !== -1 ) {
			$( this ).addClass( "ui-datepicker-prev-hover" );
		}
		if ( this.className.indexOf( "ui-datepicker-next" ) !== -1 ) {
			$( this ).addClass( "ui-datepicker-next-hover" );
		}
	}
}

/* jQuery extend now ignores nulls! */
function datepicker_extendRemove( target, props ) {
	$.extend( target, props );
	for ( var name in props ) {
		if ( props[ name ] == null ) {
			target[ name ] = props[ name ];
		}
	}
	return target;
}

/* Invoke the datepicker functionality.
   @param  options  string - a command, optionally followed by additional parameters or
					Object - settings for attaching new datepicker functionality
   @return  jQuery object */
$.fn.datepicker = function( options ) {

	/* Verify an empty collection wasn't passed - Fixes #6976 */
	if ( !this.length ) {
		return this;
	}

	/* Initialise the date picker. */
	if ( !$.datepicker.initialized ) {
		$( document ).on( "mousedown", $.datepicker._checkExternalClick );
		$.datepicker.initialized = true;
	}

	/* Append datepicker main container to body if not exist. */
	if ( $( "#" + $.datepicker._mainDivId ).length === 0 ) {
		$( "body" ).append( $.datepicker.dpDiv );
	}

	var otherArgs = Array.prototype.slice.call( arguments, 1 );
	if ( typeof options === "string" && ( options === "isDisabled" || options === "getDate" || options === "widget" ) ) {
		return $.datepicker[ "_" + options + "Datepicker" ].
			apply( $.datepicker, [ this[ 0 ] ].concat( otherArgs ) );
	}
	if ( options === "option" && arguments.length === 2 && typeof arguments[ 1 ] === "string" ) {
		return $.datepicker[ "_" + options + "Datepicker" ].
			apply( $.datepicker, [ this[ 0 ] ].concat( otherArgs ) );
	}
	return this.each( function() {
		typeof options === "string" ?
			$.datepicker[ "_" + options + "Datepicker" ].
				apply( $.datepicker, [ this ].concat( otherArgs ) ) :
			$.datepicker._attachDatepicker( this, options );
	} );
};

$.datepicker = new Datepicker(); // singleton instance
$.datepicker.initialized = false;
$.datepicker.uuid = new Date().getTime();
$.datepicker.version = "1.12.1";

return $.datepicker;

} ) );

},{}]},{},[1]);
