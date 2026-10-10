/**
 * Handles form interactions, state management, and AJAX submissions for blueprint sharing groups.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.webroot.js
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

(function ($, window, document) {
  "use strict";

  const formConfig = window.MsgdFormConfig || {};

  const TEMPLATES = Object.freeze({
    BUTTON: "#tpl-msgd-button",
    INFO_TABLE: "#tpl-msgd-info-table",
    HEADER_ACTIONS: "#tpl-msgd-header-actions",
    FEEDBACK_LOADING: "#tpl-msgd-feedback-loading",
    FEEDBACK_ERROR: "#tpl-msgd-feedback-error",
  });

  const MESSAGES = Object.freeze(formConfig.messages || {});

  const SELECTORS = Object.freeze({
    LAUNCH_BTN: "#msgdLaunchModalBtn",
    ADVANCED_CONTAINER: "#msgdAdvancedContainer",
    TOGGLE_ALL_GROUPS: "#msgdToggleAllGroups",
    GROUP_CHECKBOX: ".group-checkbox-msgd",
    OPERATION_ROW: ".msgd-operation-row",
    RESET_BTN: "#msgdResetBtn",
    MODAL_BACKDROP: ".modal-backdrop",
    STATUS: "#msgdSelectionStatus",
    STATUS_BUTTON: "#msgdSelectionStatusBtn",
    STATUS_MESSAGE: "#msgdSelectionStatusMessage",
  });

  const FormModes = Object.freeze(formConfig.modes || {});
  const DistributionLevels = Object.freeze(formConfig.distLevel || {});

  window.MsgdFormBase = {
    utils: null,
    ui: null,
    isDataLoaded: false,
    hasBlueprintPermission: false,
    blueprintExists: null,
    confirmedValues: [],
    activeValues: [],
    checkBlueprintRequest: null,
    loadGroupsRequest: null,
    preloadGroupRequest: null,

    initForm: function (activeMode) {
      this.utils = window.MsgdUtils;
      this.ui = window.MsgdFormUI;

      if (!this.utils || !this.utils.isSupportedMode(activeMode, FormModes)) {
        return;
      }

      this.abortPendingRequests();
      this.resetState();
      this.injectLaunchButton();
      this.bindEvents();

      const $form = this.utils.getActiveForm();
      const $select = $form.find(this.utils.selectors.mispSharingSelect);
      const $option = $select.find("option:selected");
      const value = $option.val();
      const hasErrors =
        $form.find(".error-message, .error, .alert-danger").length > 0;

      if (activeMode === FormModes.ADD && !hasErrors) {
        this.checkSubmitStatus();
        return;
      }

      if (value) {
        this.preloadExistingGroup(String(value), String($option.text()));
      } else {
        this.checkSubmitStatus();
      }
    },

    abortPendingRequests: function () {
      this.checkBlueprintRequest = this.utils.abortXhr(
        this.checkBlueprintRequest,
      );
      this.loadGroupsRequest = this.utils.abortXhr(this.loadGroupsRequest);
      this.preloadGroupRequest = this.utils.abortXhr(this.preloadGroupRequest);
    },

    injectLaunchButton: function () {
      const $select = $(this.utils.selectors.mispSharingSelect);

      if ($select.length && !$(SELECTORS.LAUNCH_BTN).length) {
        $select.after(this.utils.getTemplate(TEMPLATES.BUTTON));
      }
    },

    resetState: function () {
      this.abortPendingRequests();

      this.isDataLoaded = false;
      this.hasBlueprintPermission = false;
      this.blueprintExists = null;
      this.confirmedValues = [];
      this.activeValues = [];

      $(this.utils.selectors.infoContainer)
        .empty()
        .removeClass("msgd-drag-active")
        .hide();
      $(this.utils.selectors.nameInput).val("");
      $(SELECTORS.GROUP_CHECKBOX).prop("checked", false);
      $(SELECTORS.TOGGLE_ALL_GROUPS).prop("checked", false);

      this.hideStatusMessage();
      $(document).trigger("msgd:resetUiState");
    },

    getSelectedValues: function () {
      return $(SELECTORS.GROUP_CHECKBOX + ":checked")
        .map((_, element) => element.value)
        .get();
    },

    getSelectedGroupNames: function () {
      return $(SELECTORS.GROUP_CHECKBOX + ":checked")
        .map(function () {
          return this.dataset.name || "";
        })
        .get();
    },

    updateSelectedGroupName: function () {
      const name = this.getSelectedGroupNames().join(" -- ").substring(0, 191);
      $(this.utils.selectors.nameInput).val(name);
    },

    setExecuteButtonState: function (enabled, success) {
      $(this.utils.selectors.executeBtn)
        .prop("disabled", !enabled)
        .toggleClass("btn-success", success)
        .toggleClass("btn-primary", !success)
        .text(MESSAGES.BTN_SELECT || "");
    },

    showStatusMessage: function (message, type = "warning") {
      const $status = $(SELECTORS.STATUS);
      const $message = $(SELECTORS.STATUS_MESSAGE);
      const $button = $(SELECTORS.STATUS_BUTTON);
      const $icon = $button.find("i");

      if (!$status.length || !$message.length) {
        return;
      }

      const utils = this.utils || window.MsgdUtils;
      const sanitizedMessage =
        utils && typeof utils.escapeHtml === "function"
          ? utils.escapeHtml(String(message ?? ""))
          : String(message ?? "");

      $message.html(sanitizedMessage);

      $status.removeClass(
        "msgd-type-error msgd-type-warning msgd-type-success",
      );
      $icon.removeClass(
        "fa-exclamation-triangle fa-exclamation-circle fa-check-circle",
      );

      if (type === "error") {
        $status.addClass("msgd-type-error");
        $icon.addClass("fa-exclamation-circle");
      } else if (type === "success" || type === "ok") {
        $status.addClass("msgd-type-success");
        $icon.addClass("fa-check-circle");
      } else {
        $status.addClass("msgd-type-warning");
        $icon.addClass("fa-exclamation-triangle");
      }

      $status.addClass("msgd-status-visible").removeClass("msgd-status-open");
    },

    hideStatusMessage: function () {
      $(SELECTORS.STATUS).removeClass(
        "msgd-status-visible msgd-status-open msgd-type-error msgd-type-warning msgd-type-success",
      );
      $(SELECTORS.STATUS_MESSAGE).empty();
    },

    toggleStatusMessage: function () {
      const $status = $(SELECTORS.STATUS);

      if (!$status.length) {
        return;
      }

      $status.toggleClass("msgd-status-open");
    },

    bindEvents: function () {
      const self = this;
      const utils = this.utils;

      $(window)
        .off(".msgdReset")
        .on("popstate.msgdReset hashchange.msgdReset", () => self.resetState());

      $(document)
        .off(".msgdForm")
        .on("ajaxComplete.msgdForm", function (event, xhr) {
          const token = xhr?.responseJSON?.nextToken || utils.getCsrfToken();

          if (token) {
            utils.updateCsrfToken(token);
          }

          self.injectLaunchButton();
          self.checkSubmitStatus();
        })
        .on("change.msgdForm", utils.selectors.distSelect, () =>
          self.checkSubmitStatus(),
        )
        .on("change.msgdForm", SELECTORS.TOGGLE_ALL_GROUPS, () =>
          self.loadGroups(true),
        )
        .on("click.msgdForm", SELECTORS.RESET_BTN, function (event) {
          event.preventDefault();

          $("#msgdSearchInput").val("").trigger("input");
          $(SELECTORS.GROUP_CHECKBOX).prop("checked", false).trigger("change");
        })
        .on("click.msgdForm", SELECTORS.OPERATION_ROW, function (event) {
          if (
            $(event.target).is('input[type="checkbox"]') ||
            $(event.target).closest(".msgd-sg-info-btn").length
          ) {
            return;
          }

          const $checkbox = $(this).find(SELECTORS.GROUP_CHECKBOX);

          if ($checkbox.prop("disabled")) {
            return;
          }

          $checkbox
            .prop("checked", !$checkbox.prop("checked"))
            .trigger("change");
        })
        .on("change.msgdForm", SELECTORS.GROUP_CHECKBOX, () =>
          self.handleGroupSelection(),
        )
        .on("click.msgdForm", SELECTORS.STATUS_BUTTON, function (event) {
          event.preventDefault();
          event.stopPropagation();
          self.toggleStatusMessage();
        })
        .on("click.msgdForm", utils.selectors.executeBtn, function (event) {
          event.preventDefault();
          self.executeSelection();
        });

      $(utils.selectors.modal)
        .off(".msgdPlug")
        .on("show.bs.modal.msgdPlug", function () {
          $(this).appendTo("body").css("z-index", 100050);
          $(utils.selectors.infoContainer).hide();
          self.hideStatusMessage();
          self.loadGroups();
        })
        .on("shown.bs.modal.msgdPlug", function () {
          $(SELECTORS.MODAL_BACKDROP).last().css("z-index", 100049);
        })
        .on("hidden.bs.modal.msgdPlug", function () {
          $(SELECTORS.GROUP_CHECKBOX).each(function () {
            $(this).prop("checked", self.confirmedValues.includes(this.value));
          });

          self.ui.updateExternalDisplay(self.confirmedValues);
          self.hideStatusMessage();
          self.checkSubmitStatus();
        });
    },

    handleGroupSelection: function () {
      const selectedValues = this.getSelectedValues();

      this.updateSelectedGroupName();
      this.hideStatusMessage();
      this.checkBlueprintRequest = this.utils.abortXhr(
        this.checkBlueprintRequest,
      );

      if (selectedValues.length <= 1) {
        this.blueprintExists = null;

        $(SELECTORS.ADVANCED_CONTAINER).stop(true, true).slideUp(150);
        this.showStatusMessage(MESSAGES.VALID_SELECTION, "success");
        this.setExecuteButtonState(true, false);

        return;
      }

      const targetUrl = this.utils.getRouteUrl(
        this.utils.routes?.CHECK_BLUEPRINT,
      );

      if (!targetUrl) {
        this.setExecuteButtonState(false, false);
        return;
      }

      const payload = {
        data: {
          MsgdPlug: {
            groups: selectedValues,
          },
        },
      };

      const csrfToken = this.utils.getCsrfToken();

      if (csrfToken) {
        payload.data._Token = { key: csrfToken };
      }

      this.checkBlueprintRequest = $.post(targetUrl, payload)
        .done((response) => {
          this.checkBlueprintRequest = null;

          if (response?.nextToken) {
            this.utils.updateCsrfToken(response.nextToken);
          }

          if (response?.status !== this.utils.statusTypes.SUCCESS) {
            this.blueprintExists = null;
            $(SELECTORS.ADVANCED_CONTAINER).stop(true, true).slideUp(150);
            this.setExecuteButtonState(false, false);
            return;
          }

          this.blueprintExists = response.exists === true;

          if (this.blueprintExists) {
            $(SELECTORS.ADVANCED_CONTAINER).stop(true, true).slideUp(150);
            this.showStatusMessage(MESSAGES.VALID_SELECTION, "success");
            this.setExecuteButtonState(true, false);
            return;
          }

          if (!this.hasBlueprintPermission) {
            const combination = this.getSelectedGroupNames().join(" -- ");
            const message = MESSAGES.LIMITED_ACCESS
              ? MESSAGES.LIMITED_ACCESS.replace("{COMBINATION}", combination)
              : combination;

            $(SELECTORS.ADVANCED_CONTAINER).stop(true, true).slideUp(150);
            this.showStatusMessage(message, "warning");
            this.setExecuteButtonState(false, false);
            return;
          }

          $(SELECTORS.ADVANCED_CONTAINER).stop(true, true).show();
          this.showStatusMessage(MESSAGES.VALID_SELECTION, "success");
          this.setExecuteButtonState(true, false);
        })
        .fail((error) => {
          if (error?.statusText === "abort") {
            return;
          }

          this.checkBlueprintRequest = null;

          if (error?.responseJSON?.nextToken) {
            this.utils.updateCsrfToken(error.responseJSON.nextToken);
          }

          this.blueprintExists = null;
          $(SELECTORS.ADVANCED_CONTAINER).stop(true, true).slideUp(150);

          this.showStatusMessage(
            error?.responseJSON?.message || MESSAGES.EXECUTE_NETWORK_ERROR,
            "error",
          );

          this.setExecuteButtonState(false, false);
        });
    },

    loadGroups: function (forceReload = false) {
      if (this.isDataLoaded && !forceReload) {
        return;
      }

      this.loadGroupsRequest = this.utils.abortXhr(this.loadGroupsRequest);
      this.activeValues = forceReload
        ? this.getSelectedValues()
        : [...this.confirmedValues];

      const targetUrl = this.utils.getRouteUrl(
        this.utils.routes?.GET_SHARING_GROUPS,
      );

      if (!targetUrl) {
        return;
      }

      const all = $(SELECTORS.TOGGLE_ALL_GROUPS).is(":checked") ? 1 : 0;
      const $container = $(this.utils.selectors.groupsContainer);
      const permissionUrl = this.utils.getRouteUrl(
        this.utils.routes?.CHECK_USER_PERMISSION,
      );

      $container.html(this.utils.getTemplate(TEMPLATES.FEEDBACK_LOADING));

      const permissionPromise = permissionUrl
        ? $.get(permissionUrl)
            .then((response) => {
              this.hasBlueprintPermission =
                response?.status === this.utils.statusTypes.SUCCESS &&
                response?.allowed === true;
            })
            .catch(() => {
              this.hasBlueprintPermission = false;
            })
        : Promise.resolve().then(() => {
            this.hasBlueprintPermission = false;
          });

      const groupsXhr = $.get(targetUrl, { all });
      this.loadGroupsRequest = groupsXhr;

      Promise.all([permissionPromise, groupsXhr])
        .then(([, response]) => {
          this.loadGroupsRequest = null;

          if (response?.status === this.utils.statusTypes.SUCCESS) {
            this.ui.renderGroupsTable(response.groups, all, this.activeValues);
            this.isDataLoaded = true;
            return;
          }

          $container.html(
            this.utils.renderTemplate(TEMPLATES.FEEDBACK_ERROR, {
              MESSAGE: MESSAGES.LOADING_GROUPS_ERROR,
            }),
          );
        })
        .catch((error) => {
          if (error?.statusText === "abort") {
            return;
          }

          this.loadGroupsRequest = null;

          this.showStatusMessage(
            error?.responseJSON?.message || MESSAGES.NETWORK_GROUPS_ERROR,
            "error",
          );

          $container.html(
            this.utils.renderTemplate(TEMPLATES.FEEDBACK_ERROR, {
              MESSAGE: MESSAGES.NETWORK_GROUPS_ERROR,
            }),
          );
        });
    },

    executeSelection: function () {
      const targetUrl = this.utils.getRouteUrl(
        this.utils.routes?.PROCESS_GROUPS,
      );

      if (!targetUrl) {
        return;
      }

      const selectedValues = this.getSelectedValues();
      const $sharingSelect = this.utils
        .getActiveForm()
        .find(this.utils.selectors.mispSharingSelect);

      if (
        selectedValues.length > 1 &&
        this.blueprintExists === false &&
        !this.hasBlueprintPermission
      ) {
        return;
      }

      if (!selectedValues.length) {
        this.confirmedValues = [];

        $(this.utils.selectors.infoContainer).empty().hide();
        $sharingSelect.val("").trigger("change");

        this.finishExecution();
        return;
      }

      const payload = {
        data: {
          MsgdPlug: {
            groups: selectedValues,
          },
        },
      };

      const customName = String(
        $(this.utils.selectors.nameInput).val() ?? "",
      ).trim();
      const csrfToken = this.utils.getCsrfToken();

      if (customName) {
        payload.data.MsgdPlug.customName = customName;
      }

      if (csrfToken) {
        payload.data._Token = { key: csrfToken };
      }

      $.post(targetUrl, payload)
        .done((response) => {
          this.setExecuteButtonState(false, false);

          if (response?.nextToken) {
            this.utils.updateCsrfToken(response.nextToken);
          }

          if (response?.status !== this.utils.statusTypes.SUCCESS) {
            this.showStatusMessage(
              response?.message || MESSAGES.EXECUTE_FAILED,
              "error",
            );

            this.setExecuteButtonState(false, false);
            return;
          }

          this.confirmedValues = selectedValues;

          const result =
            response.group || response.groups || response.blueprint || {};
          const sharingGroupId =
            result.sharingGroupId || response.sharingGroupId;
          const sharingGroupName =
            result.sharingGroupName || response.sharingGroupName;

          if ($sharingSelect.length && sharingGroupId) {
            if (
              !$sharingSelect.find(`option[value="${sharingGroupId}"]`).length
            ) {
              $sharingSelect.append(
                new Option(sharingGroupName || "", sharingGroupId, true, true),
              );
            }

            $sharingSelect.val(sharingGroupId).trigger("change");

            this.utils
              .getActiveForm()
              .find(this.utils.selectors.distSelect)
              .val(String(DistributionLevels.SHARING_GROUP))
              .trigger("change");

            this.preloadExistingGroup(
              String(sharingGroupId),
              String(sharingGroupName || ""),
            );
          } else {
            this.ui.updateExternalDisplay(this.confirmedValues);
          }

          this.showStatusMessage(MESSAGES.EXECUTE_SUCCESS, "success");
          this.finishExecution();
        })
        .fail((error) => {
          if (error?.responseJSON?.nextToken) {
            this.utils.updateCsrfToken(error.responseJSON.nextToken);
          }

          this.showStatusMessage(
            error?.responseJSON?.message || MESSAGES.EXECUTE_NETWORK_ERROR,
            "error",
          );

          this.setExecuteButtonState(false, false);
        });
    },

    finishExecution: function () {
      this.setExecuteButtonState(false, true);

      setTimeout(() => {
        const { $modal } = this.utils.getModalRefs(this.utils.selectors.modal);

        if ($modal) {
          $modal.modal("hide");
        }
      }, 800);
    },

    checkSubmitStatus: function () {
      const $form = this.utils.getActiveForm();
      const $distSelect = $form.find(this.utils.selectors.distSelect);
      const $sharingSelect = $form.find(this.utils.selectors.mispSharingSelect);
      const $submit = $(this.utils.selectors.submitBtn);

      if ($sharingSelect.length) {
        $sharingSelect.prop("disabled", false);
      }

      const enabled =
        $distSelect.val() !== String(DistributionLevels.SHARING_GROUP) ||
        this.confirmedValues.length > 0;

      if ($submit.length) {
        $submit
          .prop("disabled", !enabled)
          .toggleClass("msgd-disabled", !enabled);
      }
    },

    preloadExistingGroup: function (sharingGroupValue, sharingGroupName) {
      this.preloadGroupRequest = this.utils.abortXhr(this.preloadGroupRequest);

      const targetUrl = this.utils.getRouteUrl(
        this.utils.routes?.GET_BLUEPRINT_RULES_GROUPS,
      );

      if (!targetUrl) {
        this.checkSubmitStatus();
        return;
      }

      this.preloadGroupRequest = $.get(targetUrl, { group: sharingGroupValue })
        .done((response) => {
          this.preloadGroupRequest = null;

          if (
            response?.status === this.utils.statusTypes.SUCCESS &&
            Array.isArray(response.groups) &&
            response.groups.length
          ) {
            const useIds = this.utils.useGroupsIds.USE_IDS;
            const mainGroup = {
              value: sharingGroupValue,
              name: sharingGroupName,
            };

            const memberGroups = response.groups.map((group) => ({
              value: String(useIds ? group.id : group.uuid).trim(),
              name: String(group.name ?? ""),
            }));

            this.confirmedValues = memberGroups.map((group) => group.value);

            const html = this.utils.renderTemplate(TEMPLATES.INFO_TABLE, {
              COUNT: String(memberGroups.length),
              HEADER_ACTIONS:
                this.utils.getTemplate(TEMPLATES.HEADER_ACTIONS) || "",
              ROWS: this.utils.buildTableRowsHtml(mainGroup, memberGroups),
            });

            $(this.utils.selectors.infoContainer)
              .html(html)
              .find(".msgd-info-table")
              .addClass("msgd-collapsed")
              .end()
              .show();

            this.utils
              .getActiveForm()
              .closest(".modal")
              .addClass("msgd-modal-expanded");
          } else {
            this.confirmedValues = [];
            $(this.utils.selectors.infoContainer).empty().hide();
          }

          this.checkSubmitStatus();
        })
        .fail((error) => {
          if (error?.statusText === "abort") {
            return;
          }

          this.showStatusMessage(
            error?.responseJSON?.message || MESSAGES.EXECUTE_NETWORK_ERROR,
            "error",
          );

          this.preloadGroupRequest = null;
          this.confirmedValues = [];

          $(this.utils.selectors.infoContainer).empty().hide();
          this.checkSubmitStatus();
        });
    },
  };

  $(function () {
    if (window.MsgdFormBase) {
      window.MsgdFormBase.initForm(formConfig.activeMode);
    }
  });
})(jQuery, window, document);
