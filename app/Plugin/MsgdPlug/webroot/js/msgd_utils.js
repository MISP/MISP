/**
 * Common utility functions, template helpers, and UI notifications.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.webroot.js
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

(function ($, window, document) {
  "use strict";

  const utilsConfig = window.MsgdUtilsConfig || {};

  const TEMPLATES = Object.freeze({
    MODAL_BLUEPRINT: "#tpl-msgd-modal-blueprint",
    MODAL_VIEW: "#tpl-msgd-modal-view",
    EYE_BUTTON: "#tpl-msgd-sg-eye-btn",
    INFO_MAIN_ROW: "#tpl-msgd-info-main-row",
    INFO_ROW: "#tpl-msgd-info-row",
    TOAST_CONTAINER: "#tpl-msgd-toast-container",
    TOAST_ITEM: "#tpl-msgd-toast-item",
  });

  const STATUS_TYPES = Object.freeze(utilsConfig.statusTypes || {});
  const ROUTES = Object.freeze(utilsConfig.routeKeys || {});
  const USE_GROUPS_IDS = Object.freeze(utilsConfig.useGroupsIds || {});

  const SELECTORS = Object.freeze({
    mispSharingSelect:
      'select[name*="sharing_group"], select[id*="SharingGroup"], select[id*="sharing_group"]',
    mispMainForms: 'form[id$="AddForm"], form[id$="EditForm"]',
    distSelect: 'select[id*="Distribution"]',
    submitBtn:
      '#submitButton, button[onclick*="AddForm"], button[onclick*="EditForm"]',
    eventViewSgLink:
      'a[href*="/sharing_groups/view/"], a[href*="/sharingGroups/view/"]',
    lockWarning: "#event_lock_warning",
    activeModalForm: ".modal:visible form",
    modal: "#msgdBlueprintModal",
    viewModal: "#msgdViewModal",
    groupsContainer: "#msgdGroupsContainer",
    infoContainer: "#msgdInfoGroupsContainer",
    nameInputWrapper: "#nameInputWrapperMsgd",
    nameInput: "#blueprintNameInputMsgd",
    executeBtn: "#msgdExecuteBtn",
  });

  window.MsgdUtils = {
    selectors: SELECTORS,
    useGroupsIds: USE_GROUPS_IDS,
    statusTypes: STATUS_TYPES,
    routes: ROUTES,

    _modalCache: {},
    _templateCache: {},

    extractIdFromSelector: function (selector) {
      if (typeof selector !== "string") return "";
      const match = selector.match(/^#([\w-]+)/);
      return match ? match[1] : "";
    },

    interpolate: function (templateString, placeholder, value) {
      if (typeof templateString !== "string") return "";
      const safeValue =
        value !== undefined && value !== null ? String(value) : "";
      return templateString.replaceAll(placeholder, safeValue);
    },

    isSupportedMode: function (mode, allowedModes) {
      if (!allowedModes || typeof allowedModes !== "object") return false;
      return Object.values(allowedModes).includes(mode);
    },

    getRouteUrl: function (routeKey) {
      const plugData = window.MsgdPlugData;
      if (
        plugData &&
        typeof plugData === "object" &&
        typeof plugData[routeKey] === "string"
      ) {
        return plugData[routeKey];
      }
      return null;
    },

    abortXhr: function (xhrRequest) {
      if (xhrRequest && typeof xhrRequest.abort === "function") {
        xhrRequest.abort();
      }
      return null;
    },

    renderTemplate: function (templateSelector, replacements = {}) {
      let htmlContent = this.getTemplate(templateSelector);
      if (!htmlContent) return "";

      Object.entries(replacements).forEach(([key, val]) => {
        const placeholder = `{{${key}}}`;
        htmlContent = this.interpolate(htmlContent, placeholder, val);
      });

      return htmlContent;
    },

    getCsrfToken: function () {
      const tokenSelector =
        'input[name="data[_Token][key]"], input[name="_Token[key]"]';
      let $token = this.getActiveForm().find(tokenSelector).first();

      if (!$token.length) {
        $token = $(tokenSelector).first();
      }

      return $token.length && $token.val() ? String($token.val()).trim() : null;
    },

    updateCsrfToken: function (newToken) {
      if (!newToken || typeof newToken !== "string") return;
      const trimmedToken = newToken.trim();
      const $tokenInputs = $(
        'input[name="data[_Token][key]"], input[name="_Token[key]"]',
      );
      if ($tokenInputs.length) {
        $tokenInputs.val(trimmedToken);
      }
    },

    ensureModalsInDOM: function () {
      const blueprintModalId = this.extractIdFromSelector(this.selectors.modal);
      const viewModalId = this.extractIdFromSelector(this.selectors.viewModal);

      if (blueprintModalId && !document.getElementById(blueprintModalId)) {
        const blueprintModalHtml = this.getTemplate(TEMPLATES.MODAL_BLUEPRINT);
        if (blueprintModalHtml) $("body").append(blueprintModalHtml);
      }
      if (viewModalId && !document.getElementById(viewModalId)) {
        const viewModalHtml = this.getTemplate(TEMPLATES.MODAL_VIEW);
        if (viewModalHtml) $("body").append(viewModalHtml);
      }
    },

    getModalRefs: function (modalSelector, bodySelector = null) {
      const cacheKey = modalSelector + "_" + (bodySelector || "");

      if (
        !this._modalCache[cacheKey] ||
        !this._modalCache[cacheKey].$modal.length
      ) {
        this.ensureModalsInDOM();
        const $modalElement = $(modalSelector);
        this._modalCache[cacheKey] = {
          $modal: $modalElement,
          $body: bodySelector ? $modalElement.find(bodySelector) : null,
        };
      }
      return this._modalCache[cacheKey];
    },

    watchLockWarning: function () {
      const lockWarningSelector = this.selectors.lockWarning;
      if (!lockWarningSelector) return;

      const lockWarningId = this.extractIdFromSelector(lockWarningSelector);
      if (lockWarningId && document.getElementById(lockWarningId)) {
        window.location.reload();
        return;
      }

      const observer = new MutationObserver((mutations, obs) => {
        if (lockWarningId && document.getElementById(lockWarningId)) {
          obs.disconnect();
          window.location.reload();
        }
      });

      observer.observe(document.body, { childList: true, subtree: true });
    },

    getActiveForm: function () {
      const $activeModalForm = $(this.selectors.activeModalForm);
      if ($activeModalForm.length) {
        return $activeModalForm.first();
      }
      const $mainForm = $(this.selectors.mispMainForms);
      return $mainForm.length ? $mainForm.first() : $("body");
    },

    escapeHtml: function (rawText) {
      if (rawText === null || rawText === undefined) return "";
      return String(rawText).replace(/[&<>"'`]/g, function (char) {
        switch (char) {
          case "&":
            return "&amp;";
          case "<":
            return "&lt;";
          case ">":
            return "&gt;";
          case '"':
            return "&quot;";
          case "'":
            return "&#039;";
          case "`":
            return "&#96;";
          default:
            return char;
        }
      });
    },

    truncate: function (rawText, limit = 35) {
      if (rawText === null || rawText === undefined) return "";
      const textContent = String(rawText);
      const characterLimit = Math.max(1, Number(limit) || 35);
      return textContent.length > characterLimit
        ? textContent.substring(0, characterLimit) + "..."
        : textContent;
    },

    getTemplate: function (selector) {
      if (typeof selector !== "string" || !selector) return "";
      if (this._templateCache[selector]) {
        return this._templateCache[selector];
      }
      const $templateElement = $(selector);
      const htmlContent = $templateElement.length
        ? $templateElement.html() || ""
        : "";
      if (htmlContent) {
        this._templateCache[selector] = htmlContent;
      }
      return htmlContent;
    },

    getEyeButtonHtml: function (groupIdOrUrl) {
      if (!groupIdOrUrl) return "";

      const targetValue = String(groupIdOrUrl).trim();
      // eslint-disable-next-line no-control-regex
      const sanitizedCheck = targetValue.replace(/[\x00-\x20\x7F-\xFF]/g, "");
      if (/^(javascript|data|vbscript|file|https?):/i.test(sanitizedCheck))
        return "";

      const baseUrl =
        window.MsgdPlugData && window.MsgdPlugData[ROUTES.SG_VIEW_BASE_URL]
          ? window.MsgdPlugData[ROUTES.SG_VIEW_BASE_URL]
          : "/sharing_groups/view";

      const rawId = targetValue
        .split("/")
        .pop()
        .replace(/[?#].*$/, "")
        .trim();
      if (!rawId) return "";

      const sharingGroupUrl = this.escapeHtml(
        baseUrl.replace(/\/$/, "") + "/" + rawId,
      );

      return this.renderTemplate(TEMPLATES.EYE_BUTTON, {
        VIEW_URL: sharingGroupUrl,
      });
    },

    buildTableRowsHtml: function (mainGroup, memberGroups) {
      let rowsHtml = "";

      if (mainGroup && mainGroup.value) {
        const mainGroupValue = mainGroup.value;
        const mainGroupName =
          mainGroup.name || mainGroup.value || "Sharing Group";

        rowsHtml += this.renderTemplate(TEMPLATES.INFO_MAIN_ROW, {
          FULL_NAME: this.escapeHtml(mainGroupName),
          TRUNCATED_NAME: this.escapeHtml(this.truncate(mainGroupName, 35)),
          EYE_BTN: this.getEyeButtonHtml(mainGroupValue),
        });
      }

      if (Array.isArray(memberGroups) && memberGroups.length > 1) {
        rowsHtml += memberGroups
          .map((group, index) => {
            if (!group || typeof group !== "object") return "";
            const groupName = group.name;
            const groupValue = group.value;

            return this.renderTemplate(TEMPLATES.INFO_ROW, {
              IDX: String(index + 1),
              FULL_NAME: this.escapeHtml(groupName),
              TRUNCATED_NAME: this.escapeHtml(this.truncate(groupName, 35)),
              EYE_BTN: this.getEyeButtonHtml(groupValue),
            });
          })
          .join("");
      }

      return rowsHtml;
    },
  };

  $(function () {
    if (window.MsgdUtils) {
      window.MsgdUtils.ensureModalsInDOM();
      window.MsgdUtils.watchLockWarning();
    }
  });
})(jQuery, window, document);
