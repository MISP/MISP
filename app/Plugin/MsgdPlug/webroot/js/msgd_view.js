/**
 * Handles view-mode logic and sharing group inspection modals.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.webroot.js
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

(function ($, window, document) {
  "use strict";

  const viewConfig = window.MsgdViewConfig || {};
  const utils = window.MsgdUtils || {};

  const TEMPLATES = Object.freeze({
    INDEX_VIEW_BTN: "#tpl-msgd-index-view-btn",
    FEEDBACK_LOADING: "#tpl-msgd-feedback-loading",
    FEEDBACK_ERROR: "#tpl-msgd-feedback-error",
    FEEDBACK_EMPTY: "#tpl-msgd-feedback-empty",
    INFO_TABLE: "#tpl-msgd-info-table",
  });

  const SELECTORS = Object.freeze({
    INDEX_VIEW_BTN: ".msgd-index-view-btn",
    MODAL_VIEW: "#msgdViewModal",
    MODAL_VIEW_BODY: "#msgdViewModalBody",
  });
  const MESSAGES = Object.freeze(viewConfig.messages || {});
  const ViewModes = Object.freeze(viewConfig.modes || {});
  const ApiRoutes = utils.routes || {};
  const MISP_SHARING_GROUP_VIEW_REGEX = /\/sharing_?groups\/view\/(\d+)/i;

  window.MsgdViewBase = {
    utils: null,
    activeRequest: null,

    initView: function (activeMode) {
      this.utils = window.MsgdUtils;
      if (!this.utils || !this.utils.isSupportedMode(activeMode, ViewModes))
        return;

      this.abortPendingRequest();

      if (activeMode === ViewModes.VIEW || activeMode === ViewModes.INDEX) {
        this.injectIndexViewButtons();
        this.bindViewEvents();
      }
    },

    abortPendingRequest: function () {
      this.activeRequest = this.utils.abortXhr(this.activeRequest);
    },

    injectIndexViewButtons: function () {
      if (!this.utils.selectors.eventViewSgLink) return;

      $(this.utils.selectors.eventViewSgLink).each((_, element) => {
        const $groupLink = $(element);

        if ($groupLink.siblings(SELECTORS.INDEX_VIEW_BTN).length) return;

        if (
          $groupLink.closest(".nav").length ||
          $groupLink.closest(".dblclickActionElement").length
        )
          return;

        const hrefAttribute = $groupLink.attr("href") || "";
        const match = hrefAttribute.match(MISP_SHARING_GROUP_VIEW_REGEX);

        if (match && match[1]) {
          const sharingGroupId = String(match[1]).trim();
          const sharingGroupName = $groupLink.text().trim();

          if (sharingGroupName !== sharingGroupId) {
            const buttonHtml = this.utils.renderTemplate(
              TEMPLATES.INDEX_VIEW_BTN,
              {
                SG_ID: this.utils.escapeHtml(sharingGroupId),
                SG_NAME: this.utils.escapeHtml(sharingGroupName),
              },
            );

            $groupLink.hide().before(buttonHtml);
          }
        }
      });
    },

    bindViewEvents: function () {
      const self = this;

      $(document)
        .off("click.msgdIndexView")
        .on("click.msgdIndexView", SELECTORS.INDEX_VIEW_BTN, function (event) {
          event.preventDefault();
          event.stopPropagation();

          const rawSharingGroupId = (this.dataset.sgId || "").trim();
          const rawSharingGroupName = (this.dataset.sgName || "").trim();

          if (!rawSharingGroupId || !/^\d+$/.test(rawSharingGroupId)) {
            return;
          }

          const { $modal, $body: $modalBody } = self.utils.getModalRefs(
            SELECTORS.MODAL_VIEW,
            SELECTORS.MODAL_VIEW_BODY,
          );

          if (!$modal || !$modalBody) {
            return;
          }

          $modalBody.html(self.utils.getTemplate(TEMPLATES.FEEDBACK_LOADING));
          $modal.modal("show");

          self.loadBlueprintGroups(
            rawSharingGroupId,
            rawSharingGroupName,
            $modalBody,
          );
        });

      const modalRefs = self.utils.getModalRefs(
        SELECTORS.MODAL_VIEW,
        SELECTORS.MODAL_VIEW_BODY,
      );
      if (modalRefs && modalRefs.$modal) {
        modalRefs.$modal
          .off("hidden.bs.modal.msgdView")
          .on("hidden.bs.modal.msgdView", function () {
            self.abortPendingRequest();
          });
      }
    },

    loadBlueprintGroups: function (
      sharingGroupValue,
      sharingGroupName,
      $modalBody,
    ) {
      const targetUrl = this.utils.getRouteUrl(
        ApiRoutes.GET_BLUEPRINT_RULES_GROUPS,
      );

      if (!targetUrl) {
        $modalBody.html(
          this.utils.renderTemplate(TEMPLATES.FEEDBACK_ERROR, {
            MESSAGE: MESSAGES.CONFIG_ERROR,
          }),
        );
        return;
      }

      this.abortPendingRequest();

      this.activeRequest = $.get(targetUrl, { group: sharingGroupValue })
        .done((response) => {
          this.activeRequest = null;

          if (
            response?.status === this.utils.statusTypes.SUCCESS &&
            Array.isArray(response.groups) &&
            response.groups.length > 0
          ) {
            const mainGroupInfo = {
              value: sharingGroupValue,
              name: sharingGroupName,
            };
            const memberGroups = response.groups.map(({ id, name }) => ({
              value: id,
              name,
            }));
            const tableRowsHtml = this.utils.buildTableRowsHtml(
              mainGroupInfo,
              memberGroups,
            );
            const infoTableHtml = this.utils.renderTemplate(
              TEMPLATES.INFO_TABLE,
              {
                COUNT: String(memberGroups.length),
                HEADER_ACTIONS: "",
                ROWS: tableRowsHtml,
              },
            );

            $modalBody.html(infoTableHtml);
          } else {
            $modalBody.html(
              this.utils.renderTemplate(TEMPLATES.FEEDBACK_EMPTY, {
                MESSAGE: MESSAGES.EMPTY_BLUEPRINT_GROUPS,
              }),
            );
          }
        })
        .fail((error) => {
          if (error && error.statusText === "abort") {
            return;
          }
          this.activeRequest = null;
          $modalBody.html(
            this.utils.renderTemplate(TEMPLATES.FEEDBACK_ERROR, {
              MESSAGE: MESSAGES.NETWORK_DETAILS_ERROR,
            }),
          );
        });
    },
  };

  $(function () {
    if (
      window.MsgdViewBase &&
      typeof window.MsgdViewBase.initView === "function"
    ) {
      window.MsgdViewBase.initView(viewConfig.activeMode);
    }
  });
})(jQuery, window, document);
