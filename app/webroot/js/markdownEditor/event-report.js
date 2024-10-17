'use strict';

// Function called to setup custom MarkdownIt rendering and parsing rules
var markdownItCustomPostInit = markdownItCustomPostInit
// Hint option passed to the CodeMirror constructor
var cmCustomHints = hintMISPElements
// Setup function called after the CodeMirror initialization
var cmCustomSetup = cmCustomSetup
// Hook allowing to alter the raw text before returning the GFM version to the user to be downloaded
var markdownGFMSubstitution = replaceMISPElementByTheirValue
// Post rendering hook called after the markdown is displayed, allowing to register listener
var markdownCustomPostRenderingListener = setupMISPElementMarkdownListeners
// Post rendering hook called after the markdown is display, allowing to perform any actions on the rendered markdown
var markdownCustomPostRenderingActions = attachRemoteMISPElements
// CodeMirror replacement/insertion actions that can be executed on the editor's text
var customReplacementActions = MISPElementReplacementActions
// Called after CodeMirror initialization to insert custom top bar buttons
var insertCustomToolbarButtons = insertMISPElementToolbarButtons

// Key of the model used by the form when saving
var modelNameForSave = 'EventReport';
// Key of the field used by the form when saving
var markdownModelFieldNameForSave = 'content';

var dotTemplateAttribute = doT.template("<span class=\"misp-element-wrapper attribute\" data-scope=\"{{=it.scope}}\" data-elementid=\"{{=it.elementid}}\"><span class=\"bold\"><span class=\"attr-type\"><span>{{=it.type}}</span></span><span class=\"blue\"><span class=\"attr-value\"><span>{{=it.value}}</span></span></span></span></span>");
var dotTemplateAttributePicture = doT.template("<div class=\"misp-picture-wrapper attributePicture\"><img data-scope=\"{{=it.scope}}\" data-elementid=\"{{=it.elementid}}\" href=\"#\" src=\"{{=it.src}}\" alt=\"{{=it.alt}}\" title=\"\"/></div>");
var dotTemplateGalaxyMatrix = doT.template("<div class=\"misp-picture-wrapper embeddedGalaxyMatrix\" data-scope=\"{{=it.scope}}\" data-elementid=\"{{=it.elementid}}\" data-eventid=\"{{=it.eventid}}\"></div>");
var dotTemplateTag = doT.template("<span class=\"tag misp-tag-wrapper embeddedTag\" data-scope=\"{{=it.scope}}\" data-elementid=\"{{!it.elementid}}\" data-eventid=\"{{=it.eventid}}\">{{=it.elementid}}</span>");
var dotTemplateObject = doT.template("<span class=\"misp-element-wrapper object\" data-scope=\"{{=it.scope}}\" data-elementid=\"{{=it.elementid}}\"><span class=\"bold\"><span class=\"obj-type\"><span>{{=it.type}}</span></span><span class=\"obj-value\"><span>{{=it.value}}</span></span></span></span>");
var dotTemplateObjectAttribute = doT.template("<span class=\"misp-element-wrapper object\" data-scope=\"{{=it.scope}}\" data-elementid=\"{{=it.elementid}}\"><span class=\"bold\"><span class=\"obj-type\"><span class=\"object-name\">{{=it.objectname}}</span>↦ <span class=\"object-attribute-type\">{{=it.type}}</span></span><span class=\"obj-value\"><span>{{=it.value}}</span></span></span></span>");
var dotTemplateInvalid = doT.template("<span class=\"misp-element-wrapper invalid\"><span class=\"bold red\">{{=it.scope}}<span class=\"blue\"> ({{=it.id}})</span></span></span>");
var dotCloseButtonTemplate = doT.template('<button type="button" class="close" style="margin-left: 5px;" data-scope=\"{{=it.scope}}\" data-elementid=\"{{!it.elementID}}\" onclick="closeThePopover(this)">×</button>');
var dotTemplateRenderingDisabled = doT.template("<span class=\"misp-element-wrapper attribute\" data-scope=\"{{=it.scope}}\" data-elementid=\"{{!it.elementid}}\" data-eventid=\"{{=it.eventid}}\">{{=it.value}}</span>");
var dotTemplateSuggestionAttribute = doT.template("<span class=\"misp-element-wrapper suggestion attribute\" data-scope=\"{{=it.scope}}\" data-indexstart=\"{{=it.indexStart}}\" data-elementid=\"{{=it.elementid}}\" data-suggestionkey=\"{{=it.suggestionkey}}\"><span class=\"bold\"><span class=\"attr-type\"><input type=\"checkbox\" {{? it.checked }}checked=\"checked\"{{?}}></input><span>{{=it.type}}</span></span><span class=\"blue\"><span class=\"attr-value\"><span>{{=it.value}}</span></span></span></span></span>");

var renderingRules = {
    'attribute': true,
    'attribute-picture': true,
    'object': true,
    'object-attribute': true,
    'tag': true,
    'galaxymatrix': true,
    'suggestion': true,
}
var galaxyMatrixTimer, tagTimers = {};
var cache_matrix = {}, cache_tag = {};
var firstCustomPostRenderCall = true;
var contentBeforeSuggestions
var typeToCategoryMapping
var entitiesFromComplexTool
var $suggestionContainer
var unreferencedElements = {
    values: null,
    context: null
};
var suggestionIDs = []
var suggestions = {}
var pickedSuggestion = { tableID: null, tr: null, entity: null, index: null, isContext: null }

/**
   _____          _      __  __ _                     
  / ____|        | |    |  \/  (_)                    
 | |     ___   __| | ___| \  / |_ _ __ _ __ ___  _ __ 
 | |    / _ \ / _` |/ _ \ |\/| | | '__| '__/ _ \| '__|
 | |___| (_) | (_| |  __/ |  | | | |  | | | (_) | |   
  \_____\___/ \__,_|\___|_|  |_|_|_|  |_|  \___/|_| 
*/

function cmCustomSetup() {
    $suggestionContainer = $('<div/>').attr('id', 'suggestion-container').addClass('hidden')
    $suggestionContainer.insertAfter('#editor-subcontainer')
}

/* Replacement actions and Toolbar addition */
function MISPElementReplacementActions(action) {
    var start = cm.getCursor('start')
    var end = cm.getCursor('end')
    var content = cm.getRange(start, end)
    var replacement = content
    var setCursorTo = false
    var noMatch = false

    switch (action) {
        case 'element':
            replacement = '@[MISPElement]()'
            end = null
            cm.replaceRange(replacement, start)
            cm.setSelection({line: start.line, ch: start.ch + 2}, {line: start.line, ch: start.ch + 2 + 11})
            cm.focus()
            return true;
        case 'attribute':
            replacement = '@[attribute]()'
            end = null
            setCursorTo = {line: start.line, ch: start.ch + replacement.length - 1}
            break;
        case 'attribute-attachment':
            replacement = '@![attribute]()'
            end = null
            setCursorTo = {line: start.line, ch: start.ch + replacement.length - 1}
            break;
        case 'object':
            replacement = '@[object]()'
            end = null
            setCursorTo = {line: start.line, ch: start.ch + replacement.length - 1}
            break;
        case 'tag':
            replacement = '@[tag]()'
            end = null
            setCursorTo = {line: start.line, ch: start.ch + replacement.length - 1}
            break;
        case 'galaxy-matrix':
            replacement = '@[galaxymatrix]()'
            end = null
            setCursorTo = {line: start.line, ch: start.ch + replacement.length - 1}
            break;
        default:
            noMatch = true;
            break;
    }
    if (noMatch) {
        return false
    }
    cm.replaceRange(replacement, start, end)
    if (setCursorTo !== false) {
        cm.setCursor(setCursorTo.line, setCursorTo.ch)
    }
    cm.focus()
    return true
}

function insertMISPElementToolbarButtons() {
    insertTopToolbarSection()
    insertTopToolbarButton('cube', 'attribute', 'Attribute')
    insertTopToolbarButton('cubes', 'object', 'Object')
    insertTopToolbarButton('image', 'attribute-attachment', 'Attribute picture')
    insertTopToolbarButton('tag', 'tag', 'Tag')
    insertTopToolbarButton('atlas', 'galaxy-matrix', 'Galaxy matrix')
}

/* Hints */
var MISPElementHints = {}
function buildMISPElementHints() {
    MISPElementHints['attribute'] = []
    Object.keys(proxyMISPElements['attribute']).forEach(function(uuid) {
        var attribute = proxyMISPElements['attribute'][uuid]
        MISPElementHints['attribute'].push(
            [attribute.value, uuid],
            [attribute.type, uuid],
            [attribute.id, uuid],
            [attribute.uuid, uuid],
        )
    })
    MISPElementHints['object'] = []
    Object.keys(proxyMISPElements['object']).forEach(function(uuid) {
        var object = proxyMISPElements['object'][uuid]
        var topPriorityValue = getTopPriorityValue(object)
        MISPElementHints['object'].push(
            [object.name, uuid],
            [object.id, uuid],
            [object.uuid, uuid],
            [topPriorityValue, uuid],
        )
    })
    MISPElementHints['galaxymatrix'] = []
    Object.keys(proxyMISPElements['galaxymatrix']).forEach(function(uuid) {
        var galaxy = proxyMISPElements['galaxymatrix'][uuid]
        MISPElementHints['galaxymatrix'].push(
            [galaxy.id, uuid],
            [galaxy.uuid, uuid],
            [galaxy.name, uuid],
            [galaxy.namespace, uuid],
            [galaxy.type, uuid],
        )
    })
    MISPElementHints['tag'] = []
    Object.keys(proxyMISPElements['tagname']).forEach(function(tagName) {
        var tag = proxyMISPElements['tagname'][tagName]
        MISPElementHints['tag'].push([tagName, tagName])
    })
}

function hintMISPElements(cm, options) {
    var authorizedMISPElements = ['attribute', 'object', 'galaxymatrix', 'tag']
    var availableScopes = ['attribute', 'object', 'galaxymatrix', 'tag']
    var reMISPElement = RegExp('@\\[(?<scope>' + authorizedMISPElements.join('|') + ')\\]\\((?<elementid>[^\\)]+)?\\)');
    var reMISPScope = RegExp('@\\[(?<scope>\\S+)\\]\\(\\)');
    var reExtendedWord = /\S/
    var hintList = []
    var scope, elementID, element
    var cursor = cm.getCursor()
    var line = cm.getLine(cursor.line)
    var start = cursor.ch
    var end = cursor.ch
    while (start && reExtendedWord.test(line.charAt(start - 1))) --start
    while (end < line.length && reExtendedWord.test(line.charAt(end))) ++end
    var word = line.slice(start, end).toLowerCase()
    
    if (word === '@[]()') {
        availableScopes.forEach(function(scope) {
            hintList.push({
                text: '@[' + scope + ']()'
            })
        });
        return {
            list: hintList,
            from: CodeMirror.Pos(cursor.line, start),
            to: CodeMirror.Pos(cursor.line, end)
        }
    }

    var resScope = reMISPScope.exec(word)
    if (resScope !== null) {
        var partialScope = resScope.groups.scope
        availableScopes.forEach(function(scope) {
            if (scope.startsWith(partialScope) && scope !== partialScope) {
                hintList.push({
                    text: '@[' + scope + ']()'
                })
            }
        });
        if (hintList.length > 0) {
            return {
                list: hintList,
                from: CodeMirror.Pos(cursor.line, start),
                to: CodeMirror.Pos(cursor.line, end)
            }
        }
    }

    var res = reMISPElement.exec(word)
    if (res !== null) {
        scope = res.groups.scope
        elementID = res.groups.elementid !== undefined ? res.groups.elementid : ''
        if (scope === 'tag') {
            element = proxyMISPElements['tagname'][elementID]
        } else {
            element = proxyMISPElements[scope][elementID]
        }
        if (element !== undefined) {
            hintList.push(
                {
                    text: '@[' + scope + '](' + element.uuid + ')',
                    render: function(elem, self, data) {
                        var hintElement = renderHintElement(scope, element)
                        $(elem).append(hintElement)
                    },
                    className: 'hint-container',
                }
            )
        } else { // search in hint arrays
            var addedItems = {}
            var maxHints = 20 + 10*(elementID.length - 3 >= 0 ? elementID.length - 3 : 0); // adapt hint numbers if typed value is large enough
            if (MISPElementHints[scope] !== undefined) {
                for (var i = 0; i < MISPElementHints[scope].length; i++) {
                    var hintArray = MISPElementHints[scope][i];
                    var hintValue = hintArray[0]
                    var hintUUID = hintArray[1]
                    if (hintList.length >= maxHints) {
                        break
                    }
                    if (hintValue.includes(elementID)) {
                        if (addedItems[hintUUID] === undefined) {
                            if (scope === 'tag') {
                                element = proxyMISPElements['tagname'][hintUUID]
                                element.uuid = hintUUID
                            } else {
                                element = proxyMISPElements[scope][hintUUID]
                            }
                            if (element !== undefined) {
                                hintList.push({
                                    text: '@[' + scope + '](' + element.uuid + ')',
                                    element: element,
                                    render: function(elem, self, data) {
                                        var hintElement = renderHintElement(scope, data.element)
                                        $(elem).append(hintElement)
                                    },
                                    className: 'hint-container',
                                })
                            }
                            addedItems[hintUUID] = true
                        }
                    }
                }
            }
        }
        return {
            list: hintList,
            from: CodeMirror.Pos(cursor.line, start),
            to: CodeMirror.Pos(cursor.line, end)
        }
    }
    return null
}

function renderHintElement(scope, element) {
    var $node;
    if (scope == 'attribute') {
        $node = $('<span/>').addClass('hint-attribute')
        if (isValidObjectAttribute(element)) {
            $node.append($('<i/>').addClass('fas fa-cubes').css('margin-right', '3px'))
        }
        $node.append($('<i/>').addClass('').text('[' + element.category + '] '))
            .append($('<span/>').addClass('bold').text(element.type + ' '))
            .append(
                $('<span/>').addClass('bold blue ellipsis-overflow')
                    .css({
                        'max-width': '500px',
                        'display': 'table-cell'
                    })
                    .text(element.value)
            )
    } else if (scope == 'object') {
        var topPriorityValue = getTopPriorityValue(element)
        $node = $('<span/>').addClass('hint-object')
        $node.append($('<i/>').addClass('').text('[' + element['meta-category'] + '] '))
            .append($('<span/>').addClass('bold').text(element.name + ' '))
            .append(
                $('<span/>').addClass('bold blue ellipsis-overflow')
                    .css({
                        'max-width': '500px',
                        'display': 'table-cell'
                    })
                    .text(topPriorityValue)
            )
    } else if (scope == 'galaxymatrix') {
        $node = $('<span/>').addClass('hint-galaxymatrix')
        $node.append($('<i/>').addClass('').text('[' + element.namespace + '] '))
            .append($('<span/>').addClass('bold').text(element.type + ' '))
            .append($('<span/>').addClass('bold blue').text(element.name))
    } else if (scope == 'tag') {
        $node = $('<span/>').addClass('hint-tag')
        $node.append(constructTagHtml(element.name, element.colour, {'box-shadow': 'none'}))
    } else {
        $node = $('<span>No match</span>') // should not happen
    }
    return $node
}

/**
  __  __            _       _                     _____ _   
 |  \/  |          | |     | |                   |_   _| |  
 | \  / | __ _ _ __| | ____| | _____      ___ __   | | | |_ 
 | |\/| |/ _` | '__| |/ / _` |/ _ \ \ /\ / / '_ \  | | | __|
 | |  | | (_| | |  |   < (_| | (_) \ V  V /| | | |_| |_| |_ 
 |_|  |_|\__,_|_|  |_|\_\__,_|\___/ \_/\_/ |_| |_|_____|\__|
 */
function markdownItCustomPostInit() {
    markdownItSetupRules()
    fetchProxyMISPElements(function() {
        doRender()
    })
}

function markdownItSetupRules() {
    md.renderer.rules.MISPElement = MISPElementRenderer;
    md.renderer.rules.MISPPictureElement = MISPPictureElementRenderer;
    md.inline.ruler.push('MISP_element_rule', MISPElementRule);
    md.core.ruler.push('MISP_element_suggestion_rule', MISPElementSuggestionRule);
}

function MISPElementSuggestionRule(state) {
    var blockTokens = state.tokens
    var tokens, blockToken, currentToken
    var indexOfAllLines, lineOffset, absoluteLine, relativeIndex
    var tokenMap
    var i, j, l
    for (i = 0, l = blockTokens.length; i < l; i++) {
        blockToken = blockTokens[i]
        if (blockToken.type !== 'inline') {
            continue
        }

        tokens = blockToken.children;
        for (j = 0; j < tokens.length; j++) {
            currentToken = tokens[j];
            if (currentToken.type !== 'MISPElement' && !currentToken.isSuggestion) {
                continue
            }
            if (blockToken.indexOfAllLines === undefined) {
                indexOfAllLines = new md.block.State(blockToken.content, md, {}, [])
                blockToken.indexOfAllLines = indexOfAllLines
            }
            lineOffset = getLineNumInArrayList(currentToken.content.indexes.start, blockToken.indexOfAllLines.bMarks)
            tokenMap = findBackClosestStartLine(blockTokens, i)
            var absoluteLine = tokenMap[0] + lineOffset
            var relativeIndex = currentToken.content.indexes.start - blockToken.indexOfAllLines.bMarks[lineOffset]
            state.tokens[i].children[j].content.indexes.lineStart = absoluteLine
            state.tokens[i].children[j].content.indexes.start = relativeIndex
        }
    }
}
/* Parsing Rules */
function MISPElementRule(state, startLine, endLine, silent) {
    var pos, start, labelStart, labelEnd, res, elementID, code, content, token, tokens, attrs, scope
    var oldPos = state.pos,
        max = state.posMax
    
    if (state.src.charCodeAt(state.pos) !== 0x40/* @ */) { return false; }
    if (state.src.charCodeAt(state.pos + 1) === 0x21/* ! */) {
        if (state.src.charCodeAt(state.pos + 2) !== 0x5B/* [ */) { return false;}
    } else {
        if (state.src.charCodeAt(state.pos + 1) !== 0x5B/* [ */) { return false; }
    }

    var isPicture = state.src.charCodeAt(state.pos + 1) === 0x21/* ! */

    if (isPicture) {
        labelStart = state.pos + 3;
        labelEnd = state.md.helpers.parseLinkLabel(state, state.pos + 2, false);
    } else {
        labelStart = state.pos + 2;
        labelEnd = state.md.helpers.parseLinkLabel(state, state.pos + 1, false);
    }

    // parser failed to find ']', so it's not a valid link
    if (labelEnd < 0) { return false; }
    scope = state.src.slice(labelStart, labelEnd)

    pos = labelEnd + 1;
    if (pos < max && state.src.charCodeAt(pos) === 0x28/* ( */) {
        start = pos;
        if (scope == 'tag' || scope == 'suggestion') { // tags may contain spaces
            res = parseDestinationValue(state.src, pos, state.posMax);
        } else {
            res = state.md.helpers.parseLinkDestination(state.src, pos, state.posMax);
        }
        if (res.ok) {
            // parseLinkDestination does not support trailing characters such as `.` after the link
            // so we have to find the matching `)`
            var destinationEnd = res.str.length - 1
            var traillingCharNumber = 0
            for (var i = res.str.length-1; i > 1; i--) {
                var code = res.str.charCodeAt(i)
                if (code === 0x29 /* ) */) {
                    destinationEnd = i
                    break
                }
                traillingCharNumber++
            }
            elementID = res.str.substring(1, destinationEnd);
            pos = res.pos - 1 - traillingCharNumber;
        }
    }

    if (pos >= max || state.src.charCodeAt(pos) !== 0x29/* ) */) {
        state.pos = oldPos;
        return false;
    }
    pos++;

    if (scope == 'tag' || scope == 'suggestion') {
        var reTagName = /^[^\n)]+$/
        if (!reTagName.test(elementID)) {
            return false;
        }
    } else {
        var reUUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/
        if (!reUUID.test(elementID)) {
            return false;
        }
    }

    // We found the end of the link, and know for a fact it's a valid link;
    // so all that's left to do is to call tokenizer.
    content = {
        scope: scope,
        elementID: elementID,
        indexes: {
            start: oldPos,
        }
    }
    if (isPicture) {
        token      = state.push('MISPPictureElement', 'div', 0);
    } else {
        token      = state.push('MISPElement', 'div', 0);
        if (scope == 'suggestion') {
            token.isSuggestion = true
            content.indexes.suggestionID = consumeSuggestionID()
        } else {
            token.isSuggestion = false
        }
    }

    token.children = tokens;
    token.content  = content;

    state.pos = pos;
    state.posMax = max;
    return true;
}

/* Rendering rules */
function MISPElementRenderer(tokens, idx, options, env, slf) {
    var allowedScope = ['attribute', 'object', 'galaxymatrix', 'tag', 'suggestion']
    var token = tokens[idx];
    var scope = token.content.scope
    var elementID = token.content.elementID
    var indexes = token.content.indexes
    if (allowedScope.indexOf(scope) == -1) {
        return renderInvalidMISPElement(scope, elementID);
    }
    return renderMISPElement(scope, elementID, indexes)
}

function MISPPictureElementRenderer(tokens, idx, options, env, slf) {
    var allowedScope = ['attribute']
    var token = tokens[idx];
    var scope = token.content.scope
    var elementID = token.content.elementID
    if (allowedScope.indexOf(scope) == -1) {
        return renderInvalidMISPElement(scope, elementID);
    }
    return renderMISPPictureElement(scope, elementID)
}

function renderMISPElement(scope, elementID, indexes) {
    var templateVariables
    if (scope == 'suggestion') {
        var suggestionKey = 'suggestion-' + String(indexes.suggestionID)
        if (suggestions[elementID] !== undefined) {
            var suggestion = suggestions[elementID][suggestionKey]
            if (suggestion !== undefined) {
                templateVariables = sanitizeObject({
                    scope: 'suggestion',
                    elementid: elementID,
                    eventid: eventid,
                    type: suggestion.complexTypeToolResult.picked_type,
                    origValue: elementID,
                    value: suggestion.complexTypeToolResult.value,
                    indexStart: indexes.start,
                    suggestionkey: suggestionKey,
                    checked: suggestion.checked
                })
                return renderTemplateBasedOnRenderingOptions(scope, dotTemplateSuggestionAttribute, templateVariables);
            }
        }
    }
    if (proxyMISPElements !== null) {
        if (scope == 'attribute') {
            var attribute = proxyMISPElements[scope][elementID]
            if (attribute !== undefined) {
                var templateToRender = dotTemplateAttribute
                var attributeData = {
                    scope: 'attribute',
                    elementid: elementID,
                    type: attribute.type,
                    value: attribute.value
                }
                if (isValidObjectAttribute(attribute)) {
                    var mispObject = getObjectFromAttribute(attribute)
                    if (mispObject !== undefined) {
                        attributeData.type = attribute.object_relation
                        attributeData.objectname = mispObject.name
                        templateToRender = dotTemplateObjectAttribute
                    }
                }
                templateVariables = sanitizeObject(attributeData)
                return renderTemplateBasedOnRenderingOptions(scope, templateToRender, templateVariables);
            }
        } else if (scope == 'object') {
            var mispObject = proxyMISPElements[scope][elementID]
            if (mispObject !== undefined) {
                var associatedTemplate = mispObject.template_uuid + '.' + mispObject.template_version
                var objectTemplate = proxyMISPElements['objectTemplates'][associatedTemplate]
                var topPriorityValue = mispObject.Attribute.length
                if (objectTemplate !== undefined) {
                    var temp = getPriorityValue(mispObject, objectTemplate)
                    topPriorityValue = temp !== false ? temp : topPriorityValue
                }
                templateVariables = sanitizeObject({
                    scope: 'object',
                    elementid: elementID,
                    type: mispObject.name,
                    value: topPriorityValue
                })
                return renderTemplateBasedOnRenderingOptions(scope, dotTemplateObject, templateVariables);
            }
        } else if (scope == 'tag') {
            templateVariables = sanitizeObject({scope: 'tag', elementid: elementID, eventid: eventid, value: elementID})
            return renderTemplateBasedOnRenderingOptions(scope, dotTemplateTag, templateVariables);
        } else if (scope == 'galaxymatrix') {
            templateVariables = sanitizeObject({scope: 'galaxymatrix', elementid: elementID, eventid: eventid, value: elementID})
            return renderTemplateBasedOnRenderingOptions(scope, dotTemplateGalaxyMatrix, templateVariables);
        }
    }
    return renderInvalidMISPElement(scope, elementID)
}

function renderMISPPictureElement(scope, elementID) {
    if (proxyMISPElements !== null) {
        var attribute = proxyMISPElements[scope][elementID]
        if (attribute !== undefined) {
            var templateVariables = sanitizeObject({
                scope: 'attribute',
                elementid: elementID,
                type: attribute.type,
                value: attribute.value,
                alt: scope + ' ' + elementID,
                src: baseurl + '/attributes/viewPicture/' + attribute.id,
                title: attribute.type + ' ' + attribute.value,
            })
            return renderTemplateBasedOnRenderingOptions('attribute-picture', dotTemplateAttributePicture, templateVariables);
        }
    }
    return renderInvalidMISPElement(scope, elementID)
}

function renderInvalidMISPElement(scope, elementID) {
    var templateVariables = sanitizeObject({
        scope: invalidMessage,
        id: elementID
    })
    return dotTemplateInvalid(templateVariables);
}

function renderTemplateBasedOnRenderingOptions(scope, templateToRender, templateVariables) {
    if (renderingRules[scope]) {
        return templateToRender(templateVariables)
    } else {
        return dotTemplateRenderingDisabled(templateVariables)
    }
}

function setupMISPElementMarkdownListeners() {
    var $elements = $('.misp-element-wrapper.attribute:not(".suggestion"), .misp-element-wrapper.object, .misp-picture-wrapper > img, .embeddedTag');
    $elements.popover({
        trigger: 'click',
        html: true,
        container: isInsideModal() ? 'body' : '#viewer-container',
        placement: 'top',
        title: getTitleFromMISPElementDOM,
        content: getContentFromMISPElementDOM
    })
    setupSuggestionMarkdownListeners()
}

function setupSuggestionMarkdownListeners() {
    $('.misp-element-wrapper').filter('.suggestion').click(function(e) {
        var $checkbox = $(this).find('input[type="checkbox"]')
        $checkbox.prop('checked', !$checkbox.prop('checked'))
        updateSuggestionCheckedState($(this), $checkbox)
    }).find('input[type="checkbox"]')
        .click(function(e) {
            e.stopPropagation()
        })
        .change(function() {
            updateSuggestionCheckedState($(this).closest('.suggestion'), $(this))
        })
}
function updateSuggestionCheckedState($wrapper, $checkbox) {
    var elementID = $wrapper.data('elementid')
    var suggestionKey = $wrapper.data('suggestionkey')
    suggestions[elementID][suggestionKey].checked = $checkbox.prop('checked')
}

function attachRemoteMISPElements() {
    $('.embeddedGalaxyMatrix[data-scope="galaxymatrix"]').each(function() {
        var $div = $(this)
        clearTimeout(galaxyMatrixTimer);
        $div.append($('<div/>').css('font-size', '24px').append(loadingSpanAnimation))
        var eventID = $div.data('eventid')
        var elementID = $div.data('elementid')
        var cacheKey = eventid + '-' + elementID
        if (cache_matrix[cacheKey] === undefined) {
            galaxyMatrixTimer = setTimeout(function() {
                attachGalaxyMatrix($div, eventID, elementID)
            }, firstCustomPostRenderCall ? 0 : slowDebounceDelay);
        } else {
            $div.html(cache_matrix[cacheKey])
        }
    })

    var tagNamesToLoad = [];
    var tagsLoading = [];
    $('.embeddedTag[data-scope="tag"]').each(function() {
        var $div = $(this);
        var elementID = $div.data('elementid');
        if (!(elementID in cache_tag)) {
            $div.append($('<span/>').append(loadingSpanAnimation));
            tagNamesToLoad.push(elementID);
            tagsLoading.push($div);
        } else {
            $div.html(cache_tag[elementID]);
        }
    }).promise().done(function() {
        if (tagNamesToLoad.length === 0) {
            return;
        }
        fetchTagInfo(tagNamesToLoad, function() {
            $.each(tagsLoading, function() {
                var $div = $(this);
                var elementID = $div.data('elementid');
                if (elementID in cache_tag) {
                    $div.html(cache_tag[elementID]);
                }
            });
        });
    });

    if (firstCustomPostRenderCall) {
        // Wait, because .each calls are asynchronous
        setTimeout(function() {
            firstCustomPostRenderCall = false;
        }, 1000)
    }
}

function attachGalaxyMatrix($elem, eventid, elementID) {
    var galaxy = proxyMISPElements['galaxymatrix'][elementID]
    if (galaxy === undefined) {
        console.log('Something wrong happened. Could not fetch galaxy from proxy')
        return
    }
    var galaxyType = galaxy.type
    $.ajax({
        data: {
            "returnFormat": "attack",
            "eventid": eventid,
            "attackGalaxy": galaxyType
        },
        success:function(data, textStatus) {
            $elem.empty().append($(data))
            $elem.find('#attackmatrix_div').css({
                'max-width': 'unset',
                'min-width': 'unset',
                'width': 'calc(100% - 5px)'
            })
            $elem.find('#checkbox_attackMatrix_showAll').click()
            $elem.find('#attackmatrix_div .heatCell').each(function() {
                if ($(this).css('background-color').length > 0 && $(this).css('background-color') != 'rgba(0, 0, 0, 0)') {
                    $(this).attr('style', 'background-color:' + $(this).css('background-color') + ' !important; color:' + $(this).css('color') + ' !important;');
                }
            })
            var cacheKey = eventid + '-' + elementID
            cache_matrix[cacheKey] = $elem.find('#attackmatrix_div')[0].outerHTML;
        },
        error: function(jqXHR, textStatus, errorThrown) {
            var templateVariables = sanitizeObject({
                scope: 'Error while fetching matrix',
                id: graphID
            })
            var placeholder = dotTemplateInvalid(templateVariables)
            $elem.empty()
                .css({'text-align': 'center'})
                .append($(placeholder))
        },
        type:"post",
        url: baseurl + "/events/restSearch"
    })
}

function fetchTagInfo(tagNames, callback) {
    $.ajax({
        data: {
            "tag": tagNames,
        },
        success: function (data) {
            var $tag, tagName;
            for (var i = 0; i < data.length; i++) {
                var tag = data[i];
                tagName = tag.Tag.name;

                proxyMISPElements['tag'][tagName] = tag;

                $tag = getTagReprensentation(tag);
                cache_tag[tagName] = $tag[0].outerHTML;
            }

            // If tag name doesn't exists, construct empty placeholder
            for (i = 0; i < tagNames.length; i++) {
                tagName = tagNames[i];
                if (!(tagName in cache_tag)) {
                    $tag = constructTagHtml(tagName, '#ffffff', {'border': '1px solid #000'});
                    cache_tag[tagName] = $tag[0].outerHTML;
                }
            }
        },
        error: function (jqXHR, textStatus, errorThrown) {
            // Query failed, fill cache with placeholder
            var tagName, templateVariables;
            for (var i = 0; i < tagNames.length; i++) {
                tagName = tagNames[i];
                if (!(tagName in cache_tag)) {
                    templateVariables = sanitizeObject({
                        scope: 'Error while fetching tag',
                        id: tagName
                    });
                    cache_tag[tagName] = dotTemplateInvalid(templateVariables);
                }
            }
        },
        complete: function () {
            if (callback !== undefined) {
                callback()
            }
        },
        type: "post",
        url: baseurl + "/tags/search/0/1/0"
    })
}


/**
   _____             _             
  / ____|           (_)            
 | (___   __ ___   ___ _ __   __ _ 
  \___ \ / _` \ \ / / | '_ \ / _` |
  ____) | (_| |\ V /| | | | | (_| |
 |_____/ \__,_| \_/ |_|_| |_|\__, |
                              __/ |
                             |___/
*/
function replaceMISPElementByTheirValue(raw) {
    var match, replacement, element
    var final = ''
    var authorizedMISPElements = ['attribute', 'object']
    var reMISPElement = RegExp('@\\[(?<scope>' + authorizedMISPElements.join('|') + ')\\]\\((?<elementid>[\\d]+)\\)', 'g');
    var offset = 0
    while ((match = reMISPElement.exec(raw)) !== null) {
        element = proxyMISPElements[match.groups.scope][match.groups.elementid]
        if (element !== undefined) {
            replacement = match.groups.scope + '-' + element.uuid
        } else {
            replacement = match.groups.scope + '-' + match.groups.elementid
        }
        final += raw.substring(offset, match.index) + replacement
        offset = reMISPElement.lastIndex
    }
    final += raw.substring(offset)
    return final
}

/**
  __  __                  
 |  \/  |                 
 | \  / | ___ _ __  _   _ 
 | |\/| |/ _ \ '_ \| | | |
 | |  | |  __/ | | | |_| |
 |_|  |_|\___|_| |_|\__,_|
 */
function injectCustomRulesMenu() {
    var $MISPElementMenuItem = createRulesMenuItem('MISP Elements', $('<img src="/favicon.ico">'), 'parser', 'MISP_element_rule')
    $markdownDropdownRulesMenu.append($MISPElementMenuItem)
    createSubMenu({
        name: 'Markdown rendering rules',
        icon: 'fab fa-markdown',
        items: [
            { name: 'Attribute', icon: 'fas fa-cube', ruleScope: 'render', ruleName: 'attribute', isToggleableRule: true },
            { name: 'Attribute picture', icon: 'fas fa-image', ruleScope: 'render', ruleName: 'attribute-picture', isToggleableRule: true },
            { name: 'Object', icon: 'fas fa-cubes', ruleScope: 'render', ruleName: 'object', isToggleableRule: true },
            { name: 'Object Attribute', icon: 'fas fa-cube', ruleScope: 'render', ruleName: 'object-attribute', isToggleableRule: true },
            { name: 'Tag', icon: 'fas fa-tag', ruleScope: 'render', ruleName: 'tag', isToggleableRule: true },
            { name: 'Galaxy matrix', icon: 'fas fa-atlas', ruleScope: 'render', ruleName: 'galaxymatrix', isToggleableRule: true },
            { name: 'Suggestion', icon: 'fas fa-magic', ruleScope: 'render', ruleName: 'suggestion', isToggleableRule: true },
        ]
    })
    createSubMenu({
        name: 'Extract entities',
        icon: 'fas fa-cogs',
        items: [
            { name: 'Manual extraction', icon: 'fas fa-highlighter', clickHandler: manualEntitiesExtraction},
            { name: 'Automatic extraction', icon: 'fas fa-magic', clickHandler: automaticEntitiesExtraction},
        ]
    })
    createSubMenu({
        name: 'LLM ',
        icon: 'fas fa-robot',
        items: [
            { name: 'Send report to LLM', icon: 'fas fa-robot', clickHandler: sendToLLM},
        ]
    })
    reloadRenderingRuleEnabledUI()
}

function markdownItToggleCustomRule(rulename, event) {
    var enabled
    if (rulename == 'MISP_element_rule') {
        var rule = getRuleStatus('inline', 'ruler', 'MISP_element_rule')
        if (rule !== false) {
            enabled = rule.enabled
        }
    }
    return {
        found: enabled !== undefined,
        enabled: enabled
    }
}


function markdownItToggleRenderingRule(rulename, event) {
    if (event !== undefined) {
        event.stopPropagation()
    }
    if (renderingRules[rulename] === undefined) {
        console.log('Rule does not exist')
        return
    }
    renderingRules[rulename] = !renderingRules[rulename]
    doRender()
    reloadRenderingRuleEnabledUI()
}

function reloadRenderingRuleEnabledUI() {
    Object.keys(renderingRules).forEach(function(rulename) {
        var enabled = renderingRules[rulename]
        if (enabled) {
            $('#markdownrendering-' + rulename + '-rendering-enabled').show()
            $('#markdownrendering-' + rulename + '-rendering-disabled').hide()
        } else {
            $('#markdownrendering-' + rulename + '-rendering-enabled').hide()
            $('#markdownrendering-' + rulename + '-rendering-disabled').show()
        }
    })
}


/**
   _____                             _   _
  / ____|                           | | (_)
 | (___  _   _  __ _  __ _  ___  ___| |_ _  ___  _ __
  \___ \| | | |/ _` |/ _` |/ _ \/ __| __| |/ _ \| '_ \
  ____) | |_| | (_| | (_| |  __/\__ \ |_| | (_) | | | |
 |_____/ \__,_|\__, |\__, |\___||___/\__|_|\___/|_| |_|
                __/ | __/ |
               |___/ |___/
 */

function automaticEntitiesExtraction() {
    var url = baseurl + '/eventReports/extractAllFromReport/' + reportid
    openGenericModal(url)
}

function manualEntitiesExtraction() {
    contentBeforeSuggestions = getEditorData()
    pickedSuggestion = { tableID: null, tr: null, entity: null, index: null, isContext: null }
    extractFromReport(function(data) {
        typeToCategoryMapping = data.typeToCategoryMapping
        prepareSuggestionInterface(data.complexTypeToolResult, data.replacementValues, data.replacementContext)
        toggleSuggestionInterface(true)
    })
}

function prepareSuggestionInterface(complexTypeToolResult, replacementValues, replacementContext) {
    toggleMarkdownEditorLoading(true, 'Processing document')
    entitiesFromComplexTool = complexTypeToolResult
    searchForUnreferencedValues(replacementValues)
    searchForUnreferencedContext(replacementContext)
    entitiesFromComplexTool = injectNumberOfOccurrencesInReport(entitiesFromComplexTool)
    setupSuggestionMarkdownListeners()
    constructSuggestionTables(entitiesFromComplexTool)
    toggleMarkdownEditorLoading(false)
}

function highlightPickedSuggestionInReport() {
    setEditorData(contentBeforeSuggestions)
    resetSuggestionIDs()
    for (var i = 0; i < entitiesFromComplexTool.length; i++) {
        var entity = entitiesFromComplexTool[i];
        if (pickedSuggestion.entity.value == entity.value) {
            var converted = convertEntityIntoSuggestion(contentBeforeSuggestions, entity)
            setEditorData(converted)
            var indicesInCM = getAllSuggestionIndicesOf(converted, entity.value, false)
            constructSuggestionMapping(entity, indicesInCM)
            break
        }
    }
}

function highlightPickedReplacementInReport() {
    var entity = pickedSuggestion.entity
    setEditorData(contentBeforeSuggestions)
    var content = contentBeforeSuggestions
    resetSuggestionIDs()
    var converted = convertEntityIntoSuggestion(content, entity)
    setEditorData(converted)
    var indicesInCM = getAllSuggestionIndicesOf(converted, entity.value, false)
    constructSuggestionMapping(entity, indicesInCM)
}

function convertEntityIntoSuggestion(content, entity) {
    var converted = ''
    var entityValue;
    if (entity.importRegexMatch) {
        entityValue = entity.importRegexMatch;
    } else if (entity.original_value) {
        entityValue = entity.original_value;
    } else {
        entityValue = entity.value;
    }
    var splittedContent = content.split(entityValue)
    splittedContent.forEach(function(text, i) {
        converted += text
        if (i < splittedContent.length-1) {
            if (isDoubleExtraction(converted)) {
                converted += entity.value
            } else {
                converted += '@[suggestion](' + entity.value + ')'
            }
        }
    })
    return converted
}

function extractFromReport(callback) {
    $.ajax({
        dataType: "json",
        beforeSend: function() {
            toggleMarkdownEditorLoading(true, 'Extracting entities')
        },
        success:function(data, textStatus) {
            callback(data);
        },
        error: function(jqXHR, textStatus, errorThrown) {
            showMessage('fail', 'Could not extract entities from report. ' + textStatus)
        },
        complete: function() {
            toggleMarkdownEditorLoading(false)
        },
        type:'get',
        url: baseurl + '/eventReports/extractFromReport/' + reportid
    })
}

function constructSuggestionMapping(entity, indicesInCM) {
    var suggestionBaseKey = 'suggestion-', suggestionKey
    suggestions[entity.value] = {}
    indicesInCM.forEach(function(index) {
        suggestionKey = suggestionBaseKey + getNewSuggestionID()
        suggestions[entity.value][suggestionKey] = {
            startIndex: index,
            endIndex: {index: index.index + entity.value.length},
            complexTypeToolResult: entity,
            checked: true
        }
    });
    setTimeout(function() {
        var notRenderedCount = suggestionIDs.length
        if (notRenderedCount > 0) {
            pickedSuggestion.tr.find('.occurrence-issues')
                .attr('title', 'Could not render ' + notRenderedCount + ' elements. Manual investigation required')
                .text('⚠ ' + notRenderedCount)
        }
    }, 300);
}

function injectNumberOfOccurrencesInReport(entities) {
    var content = getEditorData()
    entities.forEach(function(entity, i) {
        entities[i].occurrences = getAllIndicesOf(content, entity.original_value, false, false).length
    })
    return entities
}

function getAllSuggestionIndicesOf(content, entity, caseSensitive) {
    var toSearch = '@[suggestion](' + entity + ')'
    return getAllIndicesOf(content, toSearch, caseSensitive, true)
}

function toggleSuggestionInterface(enabled) {
    if (enabled) {
        setCMReadOnly(true)
        setMode('splitscreen')
        $('#editor-subcontainer').hide()
        $suggestionContainer.show()
    } else {
        setCMReadOnly(false)
        setEditorData(originalRaw)
        $('#editor-subcontainer').show()
        $suggestionContainer.hide()
        $mardownViewerToolbar.find('.btn-group:first button').css('visibility', 'visible')
        $('#suggestionCloseButton').remove()
        cm.refresh()
    }
}

function searchForUnreferencedValues(replacementValues) {
    unreferencedElements.values = {}
    var content = getEditorData()
    Object.keys(replacementValues).forEach(function(attributeValue) {
        var replacementValue = replacementValues[attributeValue]
        var indices = getAllIndicesOf(content, replacementValue.valueInReport, true, true)
        if (indices.length > 0) {
            var attributes = [];
            Object.keys(proxyMISPElements['attribute']).forEach(function(uuid) {
                if (replacementValue.attributeUUIDs.indexOf(uuid) > -1) {
                    attributes.push(proxyMISPElements['attribute'][uuid])
                }
            });
            unreferencedElements.values[replacementValue.valueInReport] = {
                attributes: attributes,
                indices: indices
            }
            if (attributeValue != replacementValue.valueInReport) {
                unreferencedElements.values[replacementValue.valueInReport].importRegexMatch = attributeValue
            }
        }
    })
}

function searchForUnreferencedContext(replacementContext) {
    unreferencedElements.context = {}
    var content = getEditorData()
    Object.keys(replacementContext).forEach(function(rawText) {
        var indices = getAllIndicesOf(content, rawText, true, true)
        if (indices.length > 0) {
            replacementContext[rawText].indices = indices
        }
    })
    unreferencedElements.context = replacementContext;
}

function pickSuggestionColumn(index, tableID, force) {
    tableID = tableID === undefined ? 'replacementTable' : tableID
    force = force === undefined ? false : force;
    if (pickedSuggestion.tableID != tableID || pickedSuggestion.index != index || force) {
        if (pickedSuggestion.tr) {
            pickedSuggestion.tr.find('.occurrence-issues').attr('title', '').text('')
        }
        var $trs = $('#' + tableID + ' tr')
        $trs.removeClass('info').find('button').prop('disabled', true)
        $trs.find('select').prop('disabled', true)
        var $tr = $('#' + tableID + ' tr[data-entityindex="' + index + '"]')
        if ($tr.length > 0) {
            $tr.addClass('info').find('button').prop('disabled', false)
            $tr.find('select').prop('disabled', false)
            pickedSuggestion = {
                tableID: tableID,
                tr: $tr,
                index: index
            }
            if (tableID === 'replacementTable') {
                var uuid = $tr.find('select.attribute-replacement').val()
                pickedSuggestion['entity'] = {
                    value: $tr.data('attributeValue'),
                    picked_type: proxyMISPElements['attribute'][uuid].type,
                    replacement: uuid
                }
                if (proxyMISPElements['attribute'][uuid].importRegexValue) {
                    pickedSuggestion['entity']['importRegexMatch'] = proxyMISPElements['attribute'][uuid].importRegexValue
                }
                highlightPickedReplacementInReport()
            } else if (tableID === 'contextReplacementTable') {
                pickedSuggestion['entity'] = {
                    value: $tr.data('contextValue'),
                    picked_type: 'tag',
                    replacement: $tr.find('select.context-replacement').val()
                }
                pickedSuggestion['isContext'] = true
                highlightPickedReplacementInReport()
            } else {
                pickedSuggestion['entity'] = $tr.data('entity')
                pickedSuggestion['entity']['picked_type'] = $tr.find('select.type').val()
                highlightPickedSuggestionInReport()
            }
        }
    }
}

function getContentWithCheckedElements(isReplacement) {
    var value = pickedSuggestion.entity.value
    var content = getEditorData()
    var contentWithPickedSuggestions = ''
    var nextIndex = 0
    var suggestionLength = '@[suggestion]()'.length + pickedSuggestion.entity.value.length
    Object.keys(suggestions[value]).forEach(function(suggestionKey, i) {
        var suggestion = suggestions[value][suggestionKey]
        contentWithPickedSuggestions += content.substr(nextIndex, suggestion.startIndex.index - nextIndex)
        nextIndex = suggestion.startIndex.index
        var renderedInMardown = $('.misp-element-wrapper.suggestion[data-suggestionkey="' + suggestionKey + '"]').length > 0;
        if (suggestion.checked && renderedInMardown) { // If the suggestion is not rendered, ignore it (could happen if parent block is escaped)
            if (isReplacement) {
                if (pickedSuggestion.isContext === true) {
                    contentWithPickedSuggestions += '@[tag](' + suggestion.complexTypeToolResult.replacement + ')'
                } else {
                    contentWithPickedSuggestions += '@[attribute](' + suggestion.complexTypeToolResult.replacement + ')'
                }
            } else {
                contentWithPickedSuggestions += content.substr(nextIndex, suggestionLength)
            }
        } else {
            contentWithPickedSuggestions += value
        }
        nextIndex += suggestionLength
    })
    contentWithPickedSuggestions += content.substr(nextIndex)
    return contentWithPickedSuggestions
}

function getSuggestionMapping() {
    var getSuggestionMapping = {}
    var $select = pickedSuggestion.tr.find('select')
    var entity = pickedSuggestion.entity
    getSuggestionMapping[entity.value] = {
        'type': $select.filter('.type').val(),
        'category': $select.filter('.category').val(),
        'to_ids': entity.to_ids
    }
    return getSuggestionMapping
}

function submitReplacement() {
    var contentWithPickedReplacements = getContentWithCheckedElements(true)
    setEditorData(contentWithPickedReplacements);
    saveMarkdown(false, function() {
        setEditorData(originalRaw)
        manualEntitiesExtraction()
    })
}

function submitExtractionSuggestion() {
    var url = baseurl + '/eventReports/replaceSuggestionInReport/' + reportid
    var contentWithPickedSuggestions = getContentWithCheckedElements(false)
    var suggestionsMapping = getSuggestionMapping()

    fetchFormDataAjax(url, function(formHTML) {
        $('body').append($('<div id="temp" style="display: none"/>').html(formHTML))
        var $tmpForm = $('#temp form')
        var formUrl = $tmpForm.attr('action')
        $tmpForm.find('[name="data[EventReport][suggestions]"]').val(JSON.stringify({
            'content': contentWithPickedSuggestions,
            'mapping': suggestionsMapping
        }))


        $.ajax({
            data: $tmpForm.serialize(),
            beforeSend: function() {
                toggleMarkdownEditorLoading(true, 'Applying suggestions in report')
            },
            success:function(postResult, textStatus) {
                if (postResult) {
                    showMessage('success', postResult.message);
                    if (postResult.data !== undefined) {
                        var report = postResult.data.report.EventReport
                        var complexTypeToolResult = postResult.data.complexTypeToolResult
                        var replacementValues = postResult.data.replacementValues
                        var replacementContext = postResult.data.replacementContext
                        lastModified = report.timestamp + '000'
                        refreshLastUpdatedField()
                        originalRaw = report.content
                        revalidateContentCache()
                        fetchProxyMISPElements(function() {
                            setEditorData(originalRaw)
                            contentBeforeSuggestions = originalRaw
                            pickedSuggestion = { tableID: null, tr: null, entity: null, index: null, isContext: null }
                            pickSuggestionColumn(-1)
                            prepareSuggestionInterface(complexTypeToolResult, replacementValues, replacementContext)
                        })
                    }
                }
            },
            error: function(jqXHR, textStatus, errorThrown) {
                if (jqXHR.responseJSON) {
                    showMessage('fail', jqXHR.responseJSON.errors);
                } else {
                    showMessage('fail', saveFailedMessage + ': ' + errorThrown);
                }
            },
            complete:function() {
                $('#temp').remove();
                toggleMarkdownEditorLoading(false)
            },
            type:"post",
            url: formUrl
        })
    })
}

function sendToLLM() {
    var url = baseurl + '/eventReports/sendToLLM/' + reportid
    openGenericModal(url)
}

/**
  _    _ _   _ _     
 | |  | | | (_) |    
 | |  | | |_ _| |___ 
 | |  | | __| | / __|
 | |__| | |_| | \__ \
  \____/ \__|_|_|___/
*/
function fetchProxyMISPElements(callback) {
    var url = baseurl + '/eventReports/getProxyMISPElements/' + reportid
    var errorMessage = 'Could not fetch MISP Elements'
    $.ajax({
        dataType: "json",
        url: url,
        data: {},
        beforeSend: function() {
            toggleMarkdownEditorLoading(true, 'Loading MISP Elements')
        },
        success: function(data) {
            if (data) {
                proxyMISPElements = data
                proxyMISPElements['tag'] = []
                buildMISPElementHints()
            } else {
                showMessage('fail', errorMessage);
            }
        },
        error: function (data, textStatus, errorThrown) {
            showMessage('fail', errorMessage + '. ' + textStatus + ": " + errorThrown);
        },
        complete: function() {
            toggleMarkdownEditorLoading(false)
            callback()
        }
    })
}

function getElementFromDom(node) {
    var scope = $(node).data('scope')
    var elementID = $(node).data('elementid')
    if (scope !== undefined && elementID !== undefined) {
        return {
            element: proxyMISPElements[scope][elementID],
            scope: scope,
            elementID: elementID
        }
    }
    return false
}

function getTitleFromMISPElementDOM() {
    var data = getElementFromDom(this)
    return buildTitleForMISPElement(data)
}

function buildTitleForMISPElement(data) {
    var title = invalidMessage
    var dismissButton = ''
    if (data !== false) {
        var templateVariables = sanitizeObject(data)
        dismissButton = dotCloseButtonTemplate(templateVariables)
        title = data.scope.charAt(0).toUpperCase() + templateVariables.scope.slice(1) + ' ' + templateVariables.elementID
    }
    return title + dismissButton
}


function closeThePopover(closeButton) {
    var scope = $(closeButton).data('scope')
    var elementID = $(closeButton).data('elementid')
    var $MISPElement = $('#viewer [data-scope="' + scope + '"][data-elementid="' + elementID.replaceAll('\"', '\\\"') + '"]')
    if ($MISPElement.length > 0) {
        $MISPElement.popover('hide');
    } else {
        $(closeButton).closest('.popover').remove()
    }
}

function constructAttributeRow(attribute, fromObject) {
    fromObject = fromObject !== undefined ? fromObject : false
    var attributeFieldsToRender = ['id', 'category', 'type'].concat(fromObject ? ['object_relation'] : [], ['value', 'comment'])
    var $tr = $('<tr/>')
    attributeFieldsToRender.forEach(function(field) {
        $tr.append(
            $('<td/>').text(attribute[field])
                .css('white-space', ['id', 'type'].indexOf(field) != -1 ? 'nowrap' : 'none')
        )
    })
    var $tags = $('<div/>')
    if (attribute.AttributeTag !== undefined) {
        attribute.AttributeTag.forEach(function(attributeTag) {
            var tag = attributeTag.Tag
            var $tag = $('<div/>').append(
                $('<span/>')
                    .addClass('tagComplete nowrap')
                    .css({'background-color': tag.colour, 'color': getTextColour(tag.colour), 'box-shadow': '1px 1px 3px #888888c4'})
                    .text(tag.name)
            )
            $tags.append($tag)
        })
    }
    $tr.append($('<td/>').append($tags))
    var $galaxies = $('<div/>')
    if (attribute.Galaxy !== undefined) {
        attribute.Galaxy.forEach(function(galaxy) {
            var $galaxy = $('<div/>').append(
                $('<span/>')
                    .addClass('tagComplete nowrap')
                    .css({'background-color': '#0088cc', 'color': getTextColour('#0088cc'), 'box-shadow': '1px 1px 3px #888888c4'})
                    .text(galaxy.name + ' :: ' + galaxy.GalaxyCluster[0].value)
            )
            $galaxies.append($galaxy)
        })
    }
    $tr.append($('<td/>').append($galaxies))
    return $tr
}

function constructAttributeHeader(attribute, showAll, fromObject) {
    showAll = showAll !== undefined ? showAll : false
    fromObject = fromObject !== undefined ? fromObject : false
    var attributeFieldsToRender = ['id', 'category', 'type'].concat(fromObject ? ['object_relation'] : [], ['value', 'comment'])
    var $tr = $('<tr/>')
    attributeFieldsToRender.forEach(function(field) {
        $tr.append($('<th/>').text(field))
    })
    if (showAll || (attribute.AttributeTag !== undefined && attribute.AttributeTag.length > 0)) {
        $tr.append($('<th/>').text('tags'))
    }
    if (showAll || (attribute.Galaxy !== undefined && attribute.Galaxy.length > 0)) {
        $tr.append($('<th/>').text('galaxies'))
    }
    var $thead = $('<thead/>').append($tr)
    return $thead
}

function constructObject(object) {
    var objectFieldsToRender = ['id', 'name', 'description', 'distribution']
    var $object = $('<div/>').addClass('similarObjectPanel')
                    .css({border: '1px solid #3465a4', 'border-radius': '5px'})
    var $top = $('<div/>').addClass('blueElement')
        .css({padding: '4px 5px'})
    objectFieldsToRender.forEach(function(field) {
        $top.append($('<div/>').append(
            $('<span/>').addClass('bold').text(field + ': '),
            $('<span/>').text(object[field])
        ))
    })
    
    var $attributeTable = $('<table/>').addClass('table table-striped table-condensed')
        .css({'margin-bottom': '3px'})
    var $thead = constructAttributeHeader({}, true, true)
    var $tbody = $('<tbody/>')
    object.Attribute.forEach(function(attribute) {
        $tbody.append(constructAttributeRow(attribute, true))
    })
    $attributeTable.append($thead, $tbody)
    $object.append($top, $attributeTable)
    return $('<div/>').append($object)
}

function getPriorityValue(mispObject, objectTemplate) {
    for (var i = 0; i < objectTemplate.ObjectTemplateElement.length; i++) {
        var object_relation = objectTemplate.ObjectTemplateElement[i].object_relation;
        for (var j = 0; j < mispObject.Attribute.length; j++) {
            var attribute = mispObject.Attribute[j];
            if (attribute.object_relation === object_relation) {
                return attribute.value
            }
        }
    }
    return false
}

function getTopPriorityValue(object) {
    var associatedTemplate = object.template_uuid + '.' + object.template_version
    var objectTemplate = proxyMISPElements['objectTemplates'][associatedTemplate]
    var topPriorityValue = object.Attribute.length > 0 ? object.Attribute[0].value : ''
    if (objectTemplate !== undefined) {
        var temp = getPriorityValue(object, objectTemplate)
        topPriorityValue = temp !== false ? temp : topPriorityValue
    }
    return topPriorityValue
}

function constructTag(tagName) {
    var tagData = proxyMISPElements['tag'][tagName]
    var $info = 'No information about this tag'
    if (tagData !== undefined) {
        if (tagData.Taxonomy !== undefined) {
            $info = constructTaxonomyInfo(tagData)
        } else if(tagData.GalaxyCluster !== undefined) {
            $info = constructGalaxyInfo(tagData)
        }
    }
    return $('<div/>').append($info)
}

function getTagReprensentation(tagData) {
    var $tag
    if (tagData.GalaxyCluster !== undefined) {
        $tag = constructClusterTagHtml(tagData)
    } else {
        var color = tagData.Tag.colour ? tagData.Tag.colour : tagData.TaxonomyPredicate.colour;
        $tag = constructTagHtml(tagData.Tag.name, color)
    }
    return $tag
}

function constructTagHtml(tagName, tagColour, additionalCSS) {
    additionalCSS = additionalCSS === undefined ? {} : additionalCSS
    var $tag = $('<span/>').text(tagName)
        .addClass('tag')
        .css({
            'background-color': tagColour,
            'color': getTextColour(tagColour),
            'box-shadow': '3px 3px 3px #888888',
        })
        .css(additionalCSS)
    return $tag
}

function constructClusterTagHtml(tagData) {
    var addBorder = false
    if (tagData.Tag.colour === undefined) {
        tagData.Tag.colour = '#ffffff'
        addBorder = true
    }
    var $tag = $('<span/>').append(
        $('<i/>').addClass('fa fa-' + tagData.GalaxyCluster.Galaxy.icon).css('margin-right', '5px'),
        $('<span/>').text(tagData.GalaxyCluster.type + ' ↦ ' + tagData.GalaxyCluster.value)
    )
        .addClass('tag')
        .css({
            'background-color': tagData.Tag.colour,
            'color': getTextColour(tagData.Tag.colour),
            'box-shadow': '3px 3px 3px #888888',
            'border': (addBorder ? '1px solid #000' : 'none')
        })
    return $tag
}

function constructTaxonomyInfo(tagData) {
    var cacheKey = eventid + '-' + tagData.Tag.name
    var tagHTML = cache_tag[cacheKey]
    var $tag = $(tagHTML)
    var $predicate = $('<div/>').append(
        $('<span/>').append($tag),
        $('<h3/>').text('Predicate info'),
        $('<p/>').append(
            $('<strong/>').text('Expanded tag: '),
            $('<span/>').text(tagData.TaxonomyPredicate.expanded),
        ),
        $('<p/>').append(
            $('<strong/>').text('Description: '),
            $('<span/>').text(tagData.TaxonomyPredicate.description),
        )
    )
    var $meta = $('<div/>').append(
        $('<h3/>').text('Taxonomy info'),
        $('<p/>').append(
            $('<strong/>').text(tagData.Taxonomy.namespace + ': '),
            $('<span/>').text(tagData.Taxonomy.description),
        )
    )
    return $('<div/>').append($predicate, $meta)
}

function constructGalaxyInfo(tagData) {
    var tagHTML = cache_tag[tagData.Tag.name]
    var $tag = $(tagHTML)
    var $cluster = $('<div/>').append(
        $('<span/>').append($tag),
        $('<h3/>').text('Cluster info'),
    )
    var fields = ['description', 'source', 'author']
    fields.forEach(function(field) {
        $cluster.append(
            $('<div/>').css({
                'max-height': '100px',
                'overflow-y': 'auto',
            })
            .append(
                $('<strong/>').text(field + ': '),
                $('<span/>').text(tagData.GalaxyCluster[field] === undefined || tagData.GalaxyCluster[field].length == 0 ? '-' : tagData.GalaxyCluster[field]),
            )
        )
    })
    var $clusterMeta = $('<div/>').css({
        'height': '100px',
        'overflow-y': 'auto',
        'resize': 'vertical',
        'border': '1px solid #0088cc',
        'border-radius': '3px',
        'padding': '5px'
    })
    if (tagData.GalaxyCluster.meta !== undefined) {
        Object.keys(tagData.GalaxyCluster.meta).forEach(function(metaKey) {
            var metaValue = tagData.GalaxyCluster.meta[metaKey]
            if (Array.isArray(metaValue)) {
                metaValue = metaValue.join(', ')
            }
            $clusterMeta.append(
                $('<div/>').append(
                    $('<strong/>').addClass('blue').text(metaKey + ': '),
                    $('<span/>').text(metaValue),
                )
            )
        })
    }
    $cluster.append($clusterMeta)
    var $galaxy = $('<div/>').append(
        $('<h3/>').text('Galaxy info'),
        $('<div/>').append(
            $('<div/>').append(
                $('<strong/>').text('Name: '),
                $('<span/>').text(tagData.GalaxyCluster.Galaxy.name),
            ),
            $('<div/>').append(
                $('<strong/>').text('Description: '),
                $('<span/>').text(tagData.GalaxyCluster.Galaxy.description),
            )
        )
    )
    return $('<div/>').append($cluster, $galaxy)
}

function getContentFromMISPElementDOM() {
    var data = getElementFromDom(this)
    return buildBodyForMISPElement(data)
}

function buildBodyForMISPElement(data) {
    if (data !== false) {
        if (data.scope == 'attribute' && isValidObjectAttribute(data.element)) {
            data.scope = 'object'
            data.element = getObjectFromAttribute(data.element)
        }
        if (data.scope == 'attribute') {
            var $thead = constructAttributeHeader(data.element)
            var $row = constructAttributeRow(data.element)
            var $attribute = $('<div/>').append(
                $('<table/>')
                    .addClass('table table-condensed')
                    .append($thead)
                    .append($('<tbody/>').append($row))
            )
            return $attribute.html()
        } else if (data.scope == 'object') {
            var $object = constructObject(data.element)
            return $object.html()
        } else if (data.scope == 'tag') {
            var $tag = constructTag(data.elementID)
            return $tag.html()
        }
    }
    return invalidMessage
}

function constructSuggestionTables(entities) {
    var $extractionTable = constructExtractionTable(entities)
    var $replacementTable = constructReplacementTable(unreferencedElements.values)
    var $contextReplacementTable = constructContextReplacementTable(unreferencedElements.context)
    var $collapsibleControl = $('<ul class="nav nav-tabs" id="suggestionTableTabs" />').append(
        $('<li/>').append(
            $('<a/>').attr('href', '#replacement-table').append(
                $('<i/>').addClass('fas fa-cube'),
                $('<span/>').text(' Data Replacement'),
                $('<span class="badge badge-important"/>').css({'padding': '2px 6px', 'margin-left': '3px'}).text(Object.keys(unreferencedElements.values).length)
            ).attr('title', 'Replace raw text into attribute reference').css('padding', '8px 8px')
        ),
        $('<li/>').append(
            $('<a/>').attr('href', '#replacement-context-table').append(
                $('<i/>').addClass('fas fa-atlas'),
                $('<span/>').text(' Context replacement'),
                $('<span class="badge badge-important"/>').css({'padding': '2px 6px', 'margin-left': '3px'}).text(Object.keys(unreferencedElements.context).length)
            ).attr('title', 'Replace raw text into context reference').css('padding', '8px 8px')
        ),
        $('<li/>').append(
            $('<a/>').attr('href', '#extraction-table').append(
                $('<i/>').addClass('fas fa-cogs'),
                $('<span/>').text(' Data extraction'),
                $('<span class="badge badge-warning"/>').css({'padding': '2px 6px', 'margin-left': '3px'}).text(entities.length)
            ).attr('title', 'Convert raw text into attribute and reference it')
        )
    )
    var $collapsibleContent = $('<div class="tab-content"/>').append(
        $('<div class="tab-pane" id="replacement-table" />').append($replacementTable),
        $('<div class="tab-pane" id="replacement-context-table" />').append($contextReplacementTable),
        $('<div class="tab-pane" id="extraction-table" />').append($extractionTable),
        $('<div class="tab-pane active" />').text('Pick a table to view available actions').css({
            'text-align': 'center',
            'opacity': '80%'
        }),
    )
    var $topBar = $('<div/>').append(
        $('<button/>').addClass('btn btn-mini btn-inverse').css({
            'float': 'right',
            'margin-top': '8px',
            'margin-right': '3px'
        }).append(
            $('<i/>').addClass('fas fa-expand-arrows-alt').css('margin-right', '5px'),
            $('<span/>').text('Fullscreen')
        ).click(toggleFullscreenMode),
        $collapsibleControl
    )
    var $div = $('<div/>').append($topBar, $collapsibleContent)
    $suggestionContainer.empty().append($div)
    addCloseSuggestionButtonToToolbar()
    $('#suggestionTableTabs a').click(function (e) {
        e.preventDefault();
        $(this).tab('show');
    })
}

function constructExtractionTable(entities) {
    var $table = $('<table/>').attr('id', 'suggestionTable').addClass('table table-striped table-condensed').css('flex-grow', '1')
    var $thead = $('<thead/>').append($('<tr/>').append(
        $('<th/>').text('Value').css('min-width', '10rem'),
        $('<th/>').text('Types'),
        $('<th/>').text('Category'),
        $('<th/>').text('Occurrences'),
        $('<th/>').text('Action')
    ))
    var $tbody = $('<tbody/>')
    entities.forEach(function(entity, index) {
        var $selectType, $selectCategory, $option
        if (entity.types.length > 1) {
            $selectType = $('<select/>').addClass('type').css('width', 'auto').prop('disabled', true).change(function() {
                var $selectCategory = $(this).closest('tr').find('select.category')
                var selected = $(this).val()
                var currentOptions = typeToCategoryMapping[selected];
                $selectCategory.empty()
                currentOptions.forEach(function(category) {
                    $selectCategory.append($('<option/>').text(category).val(category));
                })
                pickSuggestionColumn(index, 'suggestionTable', true)
            })
            entity.types.forEach(function(type) {
                $option = $('<option/>').text(type).val(type).prop('selected', type == entity.default_type)
                $selectType.append($option)
            })
        } else {
            $selectType = $('<span/>').text(entity.default_type)
                .append($('<select/>').addClass('type hidden').append($('<option/>').text(entity.default_type).val(entity.default_type)))
        }

        $selectCategory = $('<select/>').addClass('category').css('width', 'auto')
        typeToCategoryMapping[entity.default_type].forEach(function(category) {
            $option = $('<option/>').text(category).val(category)
            $selectCategory.append($option)
        })
        var $tr = $('<tr/>').attr('data-entityindex', index)
            .data('entity', entity)
            .addClass('useCursorPointer')
            .append(
                $('<td/>').addClass('bold blue').text(entity.value).css('word-wrap', 'anywhere'),
                $('<td/>').append($selectType),
                $('<td/>').append($selectCategory),
                $('<td/>').append($('<span/>').css('white-space', 'nowrap').append(
                    $('<span/>').addClass('input-prepend input-append').append(
                        $('<button type="button"/>').attr('title', 'Jump to previous occurrence').addClass('add-on btn btn-mini').css('height', 'auto').append(
                            $('<a/>').addClass('fas fa-caret-left')
                        ).click(function(e) {
                            e.stopPropagation()
                            jumpToPreviousOccurrence()
                        }),
                        $('<input type="text" disabled />').css('max-width', '2em').val(entity.occurrences),
                        $('<button type="button"/>').attr('title', 'Jump to next occurrence').addClass('add-on btn btn-mini').css('height', 'auto').append(
                            $('<a/>').addClass('fas fa-caret-right')
                        ).click(function(e) {
                            e.stopPropagation()
                            jumpToNextOccurrence()
                        })
                    ),
                    $('<span/>').addClass('occurrence-issues bold red').css({'margin-left': '3px'})
                )),
                $('<td/>').append(
                    $('<span/>').css('white-space', 'nowrap').append(
                        $('<button type="button"/>').addClass('btn')
                            .prop('disabled', true)
                            .text('Extract & Save')
                            .click(submitExtractionSuggestion)
                    )
                )
            )
        $tr.click(function() {
            var index = $(this).data('entityindex')
            pickSuggestionColumn(index, 'suggestionTable')
        })
        $tbody.append($tr)
    })
    $table.append($thead, $tbody)
    return $table
}

function constructReplacementTable(unreferencedValues) {
    var $table = $('<table/>').attr('id', 'replacementTable').addClass('table table-striped table-condensed').css('flex-grow', '1')
    var $thead = $('<thead/>').append($('<tr/>').append(
        $('<th/>').text('Value').css('min-width', '10rem'),
        $('<th/>').text('Existing attribute'),
        $('<th/>').text('Occurrences'),
        $('<th/>').text('Action')
    ))
    var $tbody = $('<tbody/>')
    Object.keys(unreferencedValues).forEach(function(value, index) {
        var $selectContainer, $select, $option
        var unreferenceValue = unreferencedValues[value]
        if(unreferenceValue.attributes.length > 1) {
            $select = $('<select/>').prop('disabled', true).addClass('attribute-replacement').css({
                'width': 'auto',
                'max-width': '300px'
            }).change(function() {
                if ($('#viewer-container .popover.in').length > 0) {
                    $(this).parent().find('.helpicon').popover('show')
                }
                pickSuggestionColumn(index, 'replacementTable', true)
            })
            unreferenceValue.attributes.forEach(function(attribute) {
                var attributeToRender = jQuery.extend(true, { }, attribute)
                attributeToRender.value = attribute.id
                $option = $('<option/>').val(attribute.uuid).append(renderHintElement('attribute', attributeToRender))
                $select.append($option)
            })
            var $helpIcon = $('<a/>').css({
                'cursor': 'help',
                'margin-left': '3px',
                'margin-top': '10px',
                'vertical-align': 'top'
            }).addClass('helpicon fas fa-question-circle')
                .popover({
                    trigger: 'click',
                    html: true,
                    container: '#viewer-container',
                    placement: 'right',
                    title: function() {
                        var uuid = $(this).parent().find('select').val()
                        var attribute = proxyMISPElements['attribute'][uuid]
                        var popoverData = {
                            element: attribute,
                            scope: 'attribute',
                            elementID: attribute.value
                        }
                        return buildTitleForMISPElement(popoverData)
                    },
                    content: function() {
                        var uuid = $(this).parent().find('select').val()
                        var attribute = proxyMISPElements['attribute'][uuid]
                        var popoverData = {
                            element: attribute,
                            scope: 'attribute',
                            elementID: attribute.value
                        }
                        return buildBodyForMISPElement(popoverData)
                    }
                })
            $selectContainer = $('<span/>').css({
                'white-space': 'nowrap'
            }).append($select, $helpIcon)
        } else {
            var attributeToRender = jQuery.extend(true, { }, unreferenceValue.attributes[0])
            attributeToRender.value = unreferenceValue.attributes[0].id
            var popoverData = {
                element: unreferenceValue.attributes[0],
                scope: 'attribute',
                elementID: unreferenceValue.attributes[0].value
            }
            $selectContainer = $('<a/>').css({'color': 'unset', 'cursor': 'help'})
                .popover({
                    trigger: 'click',
                    html: true,
                    container: '#viewer-container',
                    placement: 'right',
                    title: buildTitleForMISPElement(popoverData),
                    content: buildBodyForMISPElement(popoverData)
                })
                .append(renderHintElement('attribute', attributeToRender))
                .append($('<select/>').addClass('attribute-replacement hidden').append($('<option/>').text(unreferenceValue.attributes[0].uuid).val(unreferenceValue.attributes[0].uuid)))
        }
        var $tr = $('<tr/>').attr('data-entityindex', index)
            .data('attributeValue', value)
            .addClass('useCursorPointer')
            .append(
                $('<td/>').addClass('bold blue').text(value).css('word-wrap', 'anywhere'),
                $('<td/>').append($selectContainer),
                $('<td/>').append($('<span/>').addClass('input-prepend input-append').append(
                    $('<button type="button"/>').attr('title', 'Jump to previous occurrence').addClass('add-on btn btn-mini').css('height', 'auto').append(
                        $('<a/>').addClass('fas fa-caret-left')
                    ).click(function(e) {
                        e.stopPropagation()
                        jumpToPreviousOccurrence()
                    }),
                    $('<input type="text" disabled />').css('max-width', '2em').val(unreferenceValue.indices.length),
                    $('<button type="button"/>').attr('title', 'Jump to next occurrence').addClass('add-on btn btn-mini').css('height', 'auto').append(
                        $('<a/>').addClass('fas fa-caret-right')
                    ).click(function(e) {
                        e.stopPropagation()
                        jumpToNextOccurrence()
                    }),
                )),
                $('<td/>').append(
                    $('<span/>').css('white-space', 'nowrap').append(
                        $('<button type="button"/>').addClass('btn')
                            .prop('disabled', true)
                            .text('Replace & Save')
                            .click(submitReplacement)
                    )
                )
            )
        $tr.click(function() {
            var index = $(this).data('entityindex')
            pickSuggestionColumn(index, 'replacementTable')
        })
        $tbody.append($tr)
    })
    $table.append($thead, $tbody)
    return $table
}

function constructContextReplacementTable(unreferencedContext) {
    var $table = $('<table/>').attr('id', 'contextReplacementTable').addClass('table table-striped table-condensed').css('flex-grow', '1')
    var $thead = $('<thead/>').append($('<tr/>').append(
        $('<th/>').text('Value').css('min-width', '10rem'),
        $('<th/>').text('Existing context'),
        $('<th/>').text('Occurrences'),
        $('<th/>').text('Action')
    ))
    var $tbody = $('<tbody/>')
    Object.keys(unreferencedContext).forEach(function(rawText, index) {
        var contexts = unreferencedContext[rawText]
        var $selectContainer, $select, $option
        if(Object.keys(contexts).length > 2) {
            $select = $('<select/>').prop('disabled', true).addClass('context-replacement').css({
                'width': 'auto',
                'max-width': '300px'
            }).change(function() {
                if ($('#viewer-container .popover.in').length > 0) {
                    $(this).parent().find('.helpicon').popover('show')
                }
                pickSuggestionColumn(index, 'contextReplacementTable', true)
            })
            Object.keys(contexts).forEach(function(tagName, index) {
                if (tagName == 'indices') {
                    return
                }
                var context = contexts[tagName]
                var contextToRender = jQuery.extend(true, { }, context)
                contextToRender.value = tagName
                contextToRender.name = tagName
                $option = $('<option/>').val(tagName).text(tagName)
                $select.append($option)
            })
            $selectContainer = $('<span/>').css({
                'white-space': 'nowrap'
            }).append($select)
        } else {
            var context = jQuery.extend(true, { }, contexts)
            delete context.indices
            var tagName = Object.keys(context)[0]
            context = context[tagName]
            var contextToRender = jQuery.extend(true, { }, context)
            contextToRender.value = tagName
            contextToRender.name = tagName
            $selectContainer = $('<span/>')
                .append($('<span/>').append(constructTagHtml(tagName, contextToRender.colour)))
                .append($('<select/>').addClass('context-replacement hidden').append($('<option/>').text(tagName).val(tagName)))
        }

        var $tr = $('<tr/>').attr('data-entityindex', index)
            .data('contextValue', rawText)
            .addClass('useCursorPointer')
            .append(
                $('<td/>').addClass('bold blue').text(rawText).css('word-wrap', 'anywhere'),
                $('<td/>').append($selectContainer),
                $('<td/>').append($('<span/>').addClass('input-prepend input-append').append(
                    $('<button type="button"/>').attr('title', 'Jump to previous occurrence').addClass('add-on btn btn-mini').css('height', 'auto').append(
                        $('<a/>').addClass('fas fa-caret-left')
                    ).click(function(e) {
                        e.stopPropagation()
                        jumpToPreviousOccurrence()
                    }),
                    $('<input type="text" disabled />').css('max-width', '2em').val(contexts.indices.length),
                    $('<button type="button"/>').attr('title', 'Jump to next occurrence').addClass('add-on btn btn-mini').css('height', 'auto').append(
                        $('<a/>').addClass('fas fa-caret-right')
                    ).click(function(e) {
                        e.stopPropagation()
                        jumpToNextOccurrence()
                    }),
                )),
                $('<td/>').append(
                    $('<span/>').css('white-space', 'nowrap').append(
                        $('<button type="button"/>').addClass('btn')
                            .prop('disabled', true)
                            .text('Replace & Save')
                            .click(submitReplacement)
                    )
                )
            )
        $tr.click(function() {
            var index = $(this).data('entityindex')
            pickSuggestionColumn(index, 'contextReplacementTable')
        })
        $tbody.append($tr)
    })
    $table.append($thead, $tbody)
    return $table
}

function addCloseSuggestionButtonToToolbar() {
    var $toolbarMode = $mardownViewerToolbar.find('.btn-group:first')
    if ($toolbarMode.find('#suggestionCloseButton').length == 0) {
        $toolbarMode.find('button').css('visibility', 'hidden')
        var $closeButton = $('<button id="suggestionCloseButton" type="button"/>').addClass('btn btn-danger').css({
            position: 'absolute',
            left: 0,
            right: 0,
            top: 0,
            bottom: 0,
            width: '100%',
            height: '100%',
            'border-top-left-radius': '4px',
            'border-bottom-left-radius': '4px',
        }).attr('title', 'Close manual extraction view').text('Close extraction view').click(function() { toggleSuggestionInterface(false) })
        $toolbarMode.append($closeButton)
    }
}

function jumpToPreviousOccurrence() {
    var $suggestionsInReport = $('span.misp-element-wrapper.suggestion')
    if ($suggestionsInReport.length > 0) {
        var suggestionToScrollInto = $suggestionsInReport[0]
        var $temp = $suggestionsInReport.filter('.picked')
        if ($temp.length > 0) {
            var index = $suggestionsInReport.index($temp)
            if (index > 0) {
                suggestionToScrollInto = $suggestionsInReport[index-1]
            } else{
                suggestionToScrollInto = $suggestionsInReport[index]
            }
        }
        suggestionToScrollInto.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
        pickOccurrence($(suggestionToScrollInto))
    }
}

function jumpToNextOccurrence() {
    var $suggestionsInReport = $('span.misp-element-wrapper.suggestion')
    if ($suggestionsInReport.length > 0) {
        var suggestionToScrollInto = $suggestionsInReport[0]
        var $temp = $suggestionsInReport.filter('.picked')
        if ($temp.length > 0) {
            var index = $suggestionsInReport.index($temp)
            if ($suggestionsInReport.length-1 > index) {
                suggestionToScrollInto = $suggestionsInReport[index+1]
            } else{
                suggestionToScrollInto = $suggestionsInReport[index]
            }
        }
        suggestionToScrollInto.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
        pickOccurrence($(suggestionToScrollInto))
    } else {
        var toSearch = '@[suggestion](' + pickedSuggestion.entity.value + ')'
        var match = $('#viewer').find('*').filter(function() {
            return $(this).text().includes(toSearch)
        })
        if (match.length > 0) {
            showMessage('success', 'Suggestion element not rendered. Please check manually')
            match[0].scrollIntoView({ behavior: 'smooth', block: 'nearest' })
        } else {
            showMessage('fail', 'Could not find element')
        }
    }
}

function pickOccurrence($wrapper) {
    $('span.misp-element-wrapper.suggestion').removeClass('picked').find('.attr-type')
    $wrapper.addClass('picked')
}

function isValidObjectAttribute(attribute) {
    var mispObject = getObjectFromAttribute(attribute)
    return attribute.object_relation !== null && mispObject !== undefined
}

function getObjectFromAttribute(attribute) {
    return proxyMISPElements['object'][attribute.object_uuid]
}

function isDoubleExtraction(content) {
    var wrapperAttribute = '@[attribute]('
    var wrapperTag = '@[tag]('
    var a = content.slice(-wrapperAttribute.length)
    a = content.slice(-wrapperTag.length)

    return content.slice(-wrapperAttribute.length) == wrapperAttribute || content.slice(-wrapperTag.length) == wrapperTag
}

function getAllIndicesOf(haystack, needle, caseSensitive, requestLineNum) {
    var indices = []
    if (needle.length === 0) {
        return indices
    }
    var startIndex = 0, index = 0;
    if (!caseSensitive) {
        needle = needle.toLowerCase();
        haystack = haystack.toLowerCase();
    }
    while (true) {
        index = haystack.indexOf(needle, startIndex)
        if (index === -1) {
            break;
        }
        if (isDoubleExtraction(haystack.slice(index-10, index))) {
            startIndex = index + needle.length + 1; // +1 for closing parenthesis
            continue;
        }
        if (requestLineNum) {
            var position = cm.posFromIndex(index)
            indices.push({
                index: index,
                editorPosition: position
            });
        } else {
            indices.push(index)
        }
        startIndex = index + needle.length;
    }
    return indices;
}

function getNewSuggestionID() {
    var randomID = getRandomID()
    suggestionIDs.push(randomID)
    return randomID
}
function consumeSuggestionID() {
    return suggestionIDs.shift()
}
function resetSuggestionIDs() {
    suggestionIDs = []
}
function getRandomID() {
    return Math.random().toString(36).substr(2,9)
}

function getLineNumInArrayList(index, arrayToSearchInto) {
    for (var lineNum = 0; lineNum < arrayToSearchInto.length; lineNum++) {
        var newLineIndex = arrayToSearchInto[lineNum];
        if (index < newLineIndex) {
            return lineNum - 1
        }
    }
    return 0
}

function findBackClosestStartLine(tokens, i) {
    if (tokens[i].map !== null) {
        return tokens[i].map
    }
    var token
    for (var j = i-1; j >= 0; j--) {
        token = tokens[j]
        if (token.map !== null) {
            return token.map
        }
    }
    return null
}

function parseDestinationValue(str, pos, max) {
    var level = 0
    var lines = 0
    var code
    var start = pos
    var result = {
        ok: false,
        pos: 0,
        lines: 0,
        str: ''
      };
    while (pos < max) {
        code = str.charCodeAt(pos);

        // ascii control characters
        if (code < 0x20 || code === 0x7F) { break; }

        if (code === 0x5C /* \ */ && pos + 1 < max) {
            pos += 2;
            continue;
        }

        if (code === 0x28 /* ( */) {
            level++;
        }

        if (code === 0x29 /* ) */) {
            level--;
            if (level === 0) {
                pos++;
                break;
            }
        }

        pos++;
    }

    if (start === pos) { return result; }
    if (level !== 0) { return result; }

    result.str = str.slice(start, pos);
    result.lines = lines;
    result.pos = pos;
    result.ok = true;
    return result;
}
