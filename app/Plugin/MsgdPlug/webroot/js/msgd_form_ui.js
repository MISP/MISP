/**
 * Handles DOM rendering UI for the Form module.
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
  const MESSAGES = Object.freeze(formConfig.messages || {});

  const TEMPLATES = Object.freeze({
    OPERATION_TOOLBAR: "#tpl-msgd-operation-toolbar",
    OPERATION_WRAPPER: "#tpl-msgd-operation-wrapper",
    OPERATION_TABLE: "#tpl-msgd-operation-table",
    OPERATION_ROW: "#tpl-msgd-operation-row",
    INFO_TABLE: "#tpl-msgd-info-table",
    HEADER_ACTIONS: "#tpl-msgd-header-actions",
    FEEDBACK_EMPTY: "#tpl-msgd-feedback-empty",
  });

  const SELECTORS = Object.freeze({
    GROUPS_CONTAINER: "#msgdGroupsContainer",
    SEARCH_INPUT: "#msgdSearchInput",
    GROUP_CHECKBOX: ".group-checkbox-msgd",
    OPERATION_ROW: ".msgd-operation-row",
    INFO_TABLE: ".msgd-info-table",
    MISP_MODAL: ".modal",
    DRAG_TOGGLE: ".msgd-drag-toggle-btn",
    COLLAPSE_TOGGLE: ".msgd-collapse-toggle-btn",
    DRAG_HANDLE: "thead",
    ADVANCED_TOGGLE: "#msgdAdvancedToggleBtn",
    ADVANCED_ICON: "#msgdAdvancedIcon",
  });

  const EVENTS = Object.freeze({
    RESET: "msgd:resetUiState",
    DRAG_TOGGLE: "click.msgdFormDragToggle",
    COLLAPSE_TOGGLE: "click.msgdFormCollapseToggle",
    DRAG_START: "mousedown.msgdFormContainer",
    ADVANCED_TOGGLE: "click.msgdFormAdvToggle",
    SEARCH: "input.msgdFormSearch",
    DRAG_MOVE: "mousemove.msgdDrag",
    DRAG_END: "mouseup.msgdDrag",
  });

  window.MsgdFormUI = {
    utils: null,
    isDragEnabled: false,
    isDragging: false,
    dragStartX: 0,
    dragStartY: 0,
    searchDebounceTimeout: null,
    _searchCache: [],

    init: function () {
      this.utils = window.MsgdUtils;

      if (!this.utils) {
        return;
      }

      this.bindEvents();
    },

    bindEvents: function () {
      this.unbindEvents();
      this.bindResetEvent();
      this.bindDragEvents();
      this.bindCollapseEvent();
      this.bindAdvancedToggle();
      this.bindSearchEvent();
    },

    unbindEvents: function () {
      $(document)
        .off(EVENTS.RESET)
        .off(EVENTS.DRAG_TOGGLE, SELECTORS.DRAG_TOGGLE)
        .off(EVENTS.COLLAPSE_TOGGLE, SELECTORS.COLLAPSE_TOGGLE)
        .off(
          EVENTS.DRAG_START,
          this.utils?.selectors?.infoContainer +
            " " +
            SELECTORS.INFO_TABLE +
            " " +
            SELECTORS.DRAG_HANDLE,
        )
        .off(EVENTS.ADVANCED_TOGGLE, SELECTORS.ADVANCED_TOGGLE)
        .off(EVENTS.SEARCH, SELECTORS.SEARCH_INPUT);

      $(document).off(EVENTS.DRAG_MOVE);
      $(document).off(EVENTS.DRAG_END);

      if (this.searchDebounceTimeout) {
        clearTimeout(this.searchDebounceTimeout);
        this.searchDebounceTimeout = null;
      }

      this._searchCache = [];
    },

    bindResetEvent: function () {
      const self = this;

      $(document).on(EVENTS.RESET, function () {
        self.isDragEnabled = false;
        self.isDragging = false;
      });
    },

    bindDragEvents: function () {
      const self = this;

      $(document).on(
        EVENTS.DRAG_TOGGLE,
        SELECTORS.DRAG_TOGGLE,
        function (event) {
          event.preventDefault();
          event.stopPropagation();

          self.toggleDragMode($(this));
        },
      );

      const dragSelector =
        this.utils.selectors.infoContainer +
        " " +
        SELECTORS.INFO_TABLE +
        " " +
        SELECTORS.DRAG_HANDLE;

      $(document).on(EVENTS.DRAG_START, dragSelector, function (event) {
        self.startDragging(event);
      });
    },

    toggleDragMode: function ($button) {
      this.isDragEnabled = !this.isDragEnabled;

      $button
        .find("i")
        .toggleClass("fa-lock", !this.isDragEnabled)
        .toggleClass("fa-unlock", this.isDragEnabled);

      $(this.utils.selectors.infoContainer).toggleClass(
        "msgd-drag-active",
        this.isDragEnabled,
      );
    },

    startDragging: function (event) {
      if (!this.isDragEnabled) {
        return;
      }

      if (
        $(event.target).closest(
          SELECTORS.DRAG_TOGGLE +
            ", " +
            SELECTORS.COLLAPSE_TOGGLE +
            ", .msgd-sg-info-btn",
        ).length
      ) {
        return;
      }

      const $infoContainer = $(this.utils.selectors.infoContainer);

      if (!$infoContainer.length) {
        return;
      }

      const containerOffset = $infoContainer.offset();

      if (!containerOffset) {
        return;
      }

      this.isDragging = true;
      this.dragStartX = event.pageX - containerOffset.left;
      this.dragStartY = event.pageY - containerOffset.top;

      $("body").addClass("msgd-user-select-none");

      this.bindDraggingEvents($infoContainer);
    },

    bindDraggingEvents: function ($infoContainer) {
      const self = this;

      $(document)
        .off(EVENTS.DRAG_MOVE)
        .on(EVENTS.DRAG_MOVE, function (event) {
          if (!self.isDragging) {
            return;
          }

          $infoContainer.offset({
            top: event.pageY - self.dragStartY,
            left: event.pageX - self.dragStartX,
          });
        })
        .off(EVENTS.DRAG_END)
        .on(EVENTS.DRAG_END, function () {
          self.stopDragging();
        });
    },

    stopDragging: function () {
      this.isDragging = false;

      $("body").removeClass("msgd-user-select-none");

      $(document).off(EVENTS.DRAG_MOVE);
      $(document).off(EVENTS.DRAG_END);
    },

    bindCollapseEvent: function () {
      $(document).on(
        EVENTS.COLLAPSE_TOGGLE,
        SELECTORS.COLLAPSE_TOGGLE,
        function (event) {
          event.preventDefault();
          event.stopPropagation();

          $(this).closest(SELECTORS.INFO_TABLE).toggleClass("msgd-collapsed");
        },
      );
    },

    bindAdvancedToggle: function () {
      const self = this;

      $(document).on(
        EVENTS.ADVANCED_TOGGLE,
        SELECTORS.ADVANCED_TOGGLE,
        function (event) {
          event.preventDefault();

          $(self.utils.selectors.nameInputWrapper).slideToggle(
            150,
            function () {
              $(SELECTORS.ADVANCED_ICON).toggleClass(
                "fa-caret-right",
                "fa-caret-down",
              );
            },
          );
        },
      );
    },

    bindSearchEvent: function () {
      const self = this;

      $(document).on(EVENTS.SEARCH, SELECTORS.SEARCH_INPUT, function () {
        const searchQuery = String(this.value || "")
          .trim()
          .toLowerCase();

        if (self.searchDebounceTimeout) {
          clearTimeout(self.searchDebounceTimeout);
        }

        self.searchDebounceTimeout = setTimeout(function () {
          self.filterGroups(searchQuery);
        }, 200);
      });
    },

    buildSearchCache: function () {
      const container = document.querySelector(SELECTORS.GROUPS_CONTAINER);
      if (!container) {
        this._searchCache = [];
        return;
      }

      const rows = container.querySelectorAll(SELECTORS.OPERATION_ROW);
      const cache = [];

      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        const checkbox = row.querySelector(SELECTORS.GROUP_CHECKBOX);
        const name = checkbox?.dataset?.name
          ? checkbox.dataset.name.toLowerCase()
          : "";

        cache.push({
          element: row,
          name: name,
        });
      }

      this._searchCache = cache;
    },

    filterGroups: function (searchQuery) {
      if (!this._searchCache.length) {
        this.buildSearchCache();
      }

      const query = searchQuery.trim().toLowerCase();
      const cache = this._searchCache;
      const len = cache.length;

      for (let i = 0; i < len; i++) {
        const item = cache[i];
        const isMatch = !query || item.name.includes(query);
        const targetDisplay = isMatch ? "" : "none";

        if (item.element.style.display !== targetDisplay) {
          item.element.style.display = targetDisplay;
        }
      }
    },

    renderGroupsTable: function (
      groups,
      filterAllGroupsFlag,
      activeValues = [],
    ) {
      const useIds = Boolean(this.utils.useGroupsIds?.USE_IDS);
      const groupList = this.normalizeGroups(groups, useIds);

      this.sortGroups(groupList, activeValues);

      const rowsHtml = groupList
        .map((group) => this.renderGroupRow(group, activeValues))
        .join("");

      const toolbarHtml = this.renderToolbar(filterAllGroupsFlag);
      const contentHtml = rowsHtml
        ? this.utils.renderTemplate(TEMPLATES.OPERATION_TABLE, {
            ROWS: rowsHtml,
          })
        : this.utils.renderTemplate(TEMPLATES.FEEDBACK_EMPTY, {
            MESSAGE: MESSAGES.EMPTY_GROUPS,
          });

      const wrapperHtml = this.utils.renderTemplate(
        TEMPLATES.OPERATION_WRAPPER,
        {
          TOOLBAR: toolbarHtml,
          CONTENT: contentHtml,
        },
      );

      $(this.utils.selectors.groupsContainer).html(wrapperHtml);
      this.buildSearchCache();
    },

    normalizeGroups: function (groups, useIds) {
      if (Array.isArray(groups)) {
        return groups.map((group) => {
          if (group && typeof group === "object") {
            return {
              value: String(useIds ? group.id : group.uuid).trim(),
              name: String(group.name ?? ""),
            };
          }

          return {
            value: String(group).trim(),
            name: String(group),
          };
        });
      }

      return Object.entries(groups || {}).map(([value, name]) => ({
        value: String(value).trim(),
        name: String(name ?? ""),
      }));
    },

    sortGroups: function (groups, activeValues) {
      groups.sort(function (groupA, groupB) {
        const activeA = activeValues.includes(groupA.value);
        const activeB = activeValues.includes(groupB.value);

        if (activeA === activeB) {
          return groupA.name.localeCompare(groupB.name, undefined, {
            sensitivity: "base",
          });
        }

        return activeA ? -1 : 1;
      });
    },

    renderGroupRow: function (group, activeValues) {
      return this.utils.renderTemplate(TEMPLATES.OPERATION_ROW, {
        VALUE: this.utils.escapeHtml(group.value),
        CHECKED: activeValues.includes(group.value) ? "checked" : "",
        NAME: this.utils.escapeHtml(group.name),
      });
    },

    renderToolbar: function (filterAllGroupsFlag) {
      return this.utils.renderTemplate(TEMPLATES.OPERATION_TOOLBAR, {
        SHOW_ALL_CHECKED: filterAllGroupsFlag === 1 ? "checked" : "",
      });
    },

    updateExternalDisplay: function (confirmedValues = []) {
      const $infoContainer = $(this.utils.selectors.infoContainer);

      const confirmedGroups = this.getConfirmedGroups(confirmedValues);

      if (!confirmedGroups.length) {
        this.clearExternalDisplay($infoContainer);
        return;
      }

      this.renderExternalDisplay($infoContainer, confirmedGroups);
    },

    getConfirmedGroups: function (confirmedValues) {
      const confirmedGroups = [];

      $(SELECTORS.GROUP_CHECKBOX).each(function () {
        if (!confirmedValues.includes(this.value)) {
          return;
        }

        confirmedGroups.push({
          value: this.value,
          name: this.dataset.name || "",
        });
      });

      return confirmedGroups;
    },

    renderExternalDisplay: function ($infoContainer, confirmedGroups) {
      const $activeForm = this.utils.getActiveForm();
      const $sharingSelect = $activeForm.find(
        this.utils.selectors.mispSharingSelect,
      );

      const sharingGroupValue = String($sharingSelect.val() || "");

      const sharingGroupName =
        $sharingSelect.find("option:selected").text().trim() ||
        MESSAGES.SHARING_GROUP;

      const mainGroup = {
        value: sharingGroupValue,
        name: sharingGroupName,
      };

      const html = this.utils.renderTemplate(TEMPLATES.INFO_TABLE, {
        COUNT: String(confirmedGroups.length),
        HEADER_ACTIONS: this.utils.getTemplate(TEMPLATES.HEADER_ACTIONS) || "",
        ROWS: this.utils.buildTableRowsHtml(mainGroup, confirmedGroups),
      });

      $infoContainer.html(html).show();

      $activeForm.closest(SELECTORS.MISP_MODAL).addClass("msgd-modal-expanded");
    },

    clearExternalDisplay: function ($infoContainer) {
      $infoContainer.empty().hide();

      this.utils
        .getActiveForm()
        .closest(SELECTORS.MISP_MODAL)
        .removeClass("msgd-modal-expanded");
    },
  };

  $(function () {
    if (window.MsgdFormUI) {
      window.MsgdFormUI.init();
    }
  });
})(jQuery, window, document);
