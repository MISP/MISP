<?php
    echo $this->element('genericElements/assetLoader', [
        'css' => ['main-beta', 'components-beta', 'query-builder.default', 'attack_matrix', 'analyst-data'],
        'js' => ['doT', 'extendext', 'moment.min', 'query-builder', 'network-distribution-graph', 'd3', 'd3.custom', 'jquery-ui.min', 'event-timestamps', 'd3-sankey.min'],
    ]);
?>

<style>
    .beta-view-events {
        padding: 20px 20px 84px;
        background-color: #f9f9f9;
        min-height: 100vh;
    }
    .beta-sankey-shell {
        position: relative;
        width: 100%;
        overflow: visible;
    }
    .beta-sankey-stage {
        display: none;
        width: 100%;
        margin: 0 0 18px;
        text-align: center;
    }
    #correlations.beta-tab-pane-tight {
        padding-top: 6px;
    }
    #correlations.beta-tab-pane-tight #correlations-content {
        margin-top: 0;
    }
    #correlations.beta-tab-pane-tight #correlations-sankey-stage {
        margin-top: 0;
    }
    #correlations.beta-tab-pane-tight #correlations-sankey-toolbar {
        margin-top: 0;
        margin-bottom: 4px;
        min-height: 20px;
    }
    #correlations.beta-tab-pane-tight .beta-event-timeline {
        margin-top: 0;
    }
    .beta-header-container {
        margin-bottom: 18px;
        padding: 14px 16px 12px;
        border: 1px solid #c8d8e8;
        border-radius: 16px;
        background: linear-gradient(180deg, #eef5fc 0%, #dde8f4 100%);
        box-shadow: 0 8px 18px rgba(72, 101, 134, 0.14), 0 1px 3px rgba(72, 101, 134, 0.08), inset 0 1px 0 rgba(255, 255, 255, 0.82);
        position: relative;
        overflow: hidden;
    }
    .beta-header-container::after {
        content: "";
        position: absolute;
        left: 18px;
        right: 18px;
        bottom: 0;
        height: 2px;
        background: linear-gradient(90deg, rgba(91, 121, 156, 0) 0%, rgba(91, 121, 156, 0.55) 14%, rgba(91, 121, 156, 0.72) 50%, rgba(91, 121, 156, 0.55) 86%, rgba(91, 121, 156, 0) 100%);
        pointer-events: none;
    }
    .beta-event-header-row {
        display: flex;
        flex-wrap: wrap;
        align-items: flex-start;
        justify-content: space-between;
        gap: 12px;
    }
    .beta-event-metadata-panel {
        flex: 1 1 420px;
        display: flex;
        flex-direction: column;
        gap: 10px;
        padding: 14px 16px;
        border: 1px solid #c0d2e4;
        border-radius: 10px 10px 0 0;
        border-bottom-color: #d8e4ef;
        background: linear-gradient(180deg, #ffffff 0%, #e8f1f9 100%);
        box-shadow: 0 6px 14px rgba(77, 106, 139, 0.13), 0 1px 2px rgba(77, 106, 139, 0.08), inset 0 1px 0 rgba(255, 255, 255, 0.84);
    }
    .beta-event-title {
        font-weight: 600;
        margin-top: 0;
        margin-bottom: 4px;
        font-size: 0.95em;
        line-height: 1.2;
        color: #24384d;
        text-shadow: 0 1px 0 rgba(255, 255, 255, 0.55);
    }
    .beta-event-subtitle {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
        margin-bottom: 0;
    }
    .beta-event-subtitle-chips {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        min-width: 0;
    }
    .beta-event-header-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        align-items: stretch;
        justify-content: flex-end;
        margin-top: 0;
    }
    .beta-event-header-control {
        display: inline-flex;
        align-items: center;
        gap: 7px;
        height: 36px;
        padding: 0 12px;
        border: 1px solid #d2dfec;
        border-radius: 999px;
        box-sizing: border-box;
        background: linear-gradient(180deg, #ffffff 0%, #f2f6fa 100%);
        color: #4b5f77;
        font-size: 12px;
        font-weight: 700;
        white-space: nowrap;
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.8);
    }
    .beta-event-header-control .fa {
        color: #6d8297;
    }
    .beta-event-header-control-link {
        text-decoration: none;
    }
    .beta-event-header-control-link:hover,
    .beta-event-header-control-link:focus,
    .beta-event-header-control.is-interactive:hover,
    .beta-event-header-control.is-interactive:focus-within {
        color: #2b4f81;
        text-decoration: none;
        background: linear-gradient(180deg, #ffffff 0%, #eaf2fb 100%);
        border-color: #bdd2e8;
    }
    .beta-event-header-control.is-publish {
        padding-right: 8px;
    }
    .beta-id-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        height: 36px;
        padding: 0 12px;
        border: 1px solid #d9e2ec;
        border-radius: 999px;
        box-sizing: border-box;
        background: linear-gradient(180deg, #fbfcfe 0%, #f2f5f8 100%);
        font-size: 11px;
        color: #566372;
        font-weight: 600;
        line-height: 1;
    }
    .beta-id-badge-label {
        text-transform: uppercase;
        letter-spacing: 0.03em;
        font-size: 10px;
        color: #8a97a5;
    }
    .beta-id-badge-value {
        font-family: Menlo, Monaco, Consolas, "Liberation Mono", monospace;
        color: #41505f;
    }
    .beta-event-meta-row {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        align-items: center;
        margin-top: 0;
        padding: 8px 14px;
        border: 1px solid #c7d8e8;
        border-top: 0;
        border-radius: 0 0 10px 10px;
        background: linear-gradient(180deg, #f8fbff 0%, #edf4fa 100%);
        box-shadow: 0 5px 12px rgba(77, 106, 139, 0.09), 0 1px 2px rgba(77, 106, 139, 0.06), inset 0 1px 0 rgba(255, 255, 255, 0.8);
    }
    .beta-meta-group {
        display: flex;
        align-items: center;
        gap: 10px;
        flex: 1 1 280px;
        min-width: 0;
        padding: 2px 10px 2px 0;
    }
    .beta-meta-group.beta-meta-group-when {
        flex: 0.9 1 240px;
    }
    .beta-meta-group.beta-meta-group-who {
        flex: 1.35 1 380px;
    }
    .beta-meta-group.beta-meta-group-scope {
        flex: 0.75 1 220px;
    }
    .beta-meta-group + .beta-meta-group {
        border-left: 1px solid #e2eaf2;
        padding-left: 14px;
    }
    .beta-meta-group.beta-meta-group-scope {
        justify-content: flex-end;
    }
    .beta-meta-group.beta-meta-group-scope .beta-meta-items {
        justify-content: flex-end;
    }
    .beta-meta-group-title {
        display: inline-flex;
        align-items: center;
        margin-bottom: 0;
        flex: 0 0 auto;
        color: #7f8c99;
    }
    .beta-meta-group-title .fa {
        width: 12px;
        text-align: center;
        color: #7a8a9a;
        font-size: 11px;
    }
    .beta-meta-items {
        display: flex;
        flex-wrap: wrap;
        gap: 4px 0;
        align-items: center;
        min-width: 0;
    }
    .beta-meta-item {
        display: inline-flex;
        flex-wrap: wrap;
        align-items: center;
        align-self: center;
        gap: 4px;
        min-width: 0;
        color: #5d6b79;
        font-size: 13px;
        line-height: 1.4;
        position: relative;
    }
    .beta-meta-item + .beta-meta-item {
        margin-left: 12px;
        padding-left: 14px;
    }
    .beta-meta-item + .beta-meta-item::before {
        content: "";
        position: absolute;
        left: 0;
        top: 50%;
        width: 1px;
        height: 14px;
        background: #d7e0ea;
        transform: translateY(-50%);
    }
    .beta-sankey-toggle {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        color: #61707e;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        user-select: none;
    }
    .beta-sankey-toggle-group {
        margin-left: auto;
        display: inline-flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
    }
    .beta-sankey-toggle input {
        position: absolute;
        opacity: 0;
        width: 1px;
        height: 1px;
        pointer-events: none;
    }
    .beta-sankey-toggle-label {
        white-space: nowrap;
    }
    .beta-sankey-toggle-switch {
        position: relative;
        width: 42px;
        height: 24px;
        border-radius: 999px;
        background: #c7d0d9;
        box-shadow: inset 0 0 0 1px rgba(56, 73, 91, 0.08);
        transition: background 160ms ease, box-shadow 160ms ease;
    }
    .beta-sankey-toggle-switch::after {
        content: '';
        position: absolute;
        top: 2px;
        left: 2px;
        width: 20px;
        height: 20px;
        border-radius: 50%;
        background: #fff;
        box-shadow: 0 1px 3px rgba(22, 32, 43, 0.28);
        transition: transform 160ms ease;
    }
    .beta-sankey-toggle input:checked + .beta-sankey-toggle-switch {
        background: #4cd964;
    }
    .beta-sankey-toggle input:checked + .beta-sankey-toggle-switch::after {
        transform: translateX(18px);
    }
    .beta-sankey-toggle input:focus + .beta-sankey-toggle-switch {
        box-shadow: inset 0 0 0 1px rgba(56, 73, 91, 0.08), 0 0 0 3px rgba(76, 217, 100, 0.18);
    }
    .beta-event-timeline-current-marker {
        position: absolute;
        top: 0;
        bottom: 0;
        width: 0;
        border-left: 2px dashed rgba(111, 190, 128, 0.95);
        pointer-events: none;
        z-index: 1;
    }
    .beta-event-timeline-current-marker::before {
        content: '';
        position: absolute;
        top: -5px;
        left: -4px;
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: #6fbe80;
        box-shadow: 0 0 0 2px rgba(255, 255, 255, 0.95);
    }
    .beta-event-timeline-current-label {
        position: absolute;
        top: -42px;
        transform: translateX(-50%);
        padding: 2px 8px;
        border-radius: 999px;
        background: rgba(111, 190, 128, 0.96);
        color: #1d4b29;
        font-size: 10px;
        font-weight: 700;
        line-height: 1.2;
        white-space: nowrap;
        pointer-events: none;
        z-index: 2;
        box-shadow: 0 2px 8px rgba(29, 75, 41, 0.18);
        transform-origin: center bottom;
        rotate: -22deg;
    }
    .beta-meta-item-label {
        color: #8c98a5;
        font-size: 11px;
        font-weight: 700;
    }
    .beta-meta-item-value {
        color: #384553;
        font-size: 14px;
        font-weight: 600;
        min-width: 0;
        display: inline-flex;
        align-items: center;
    }
    .beta-meta-item-value a {
        font-weight: 600;
    }
    .beta-meta-item-value.beta-meta-item-value-inline {
        display: inline-flex;
        align-items: center;
        gap: 6px;
    }
    .beta-meta-org-link {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        min-width: 0;
    }
    .beta-meta-org-link img {
        flex: 0 0 auto;
        width: 20px;
        height: 20px;
        border-radius: 4px;
        object-fit: contain;
        background: #fff;
        border: 1px solid #dde5ee;
    }
    .beta-meta-item-value.beta-relative-timestamp {
        display: inline-flex;
        align-items: center;
    }
    @media (max-width: 1024px) {
        .beta-meta-group {
            flex-basis: 100%;
        }
        .beta-meta-group + .beta-meta-group {
            border-left: 0;
            padding-left: 0;
        }
        .beta-meta-group.beta-meta-group-scope,
        .beta-meta-group.beta-meta-group-scope .beta-meta-items {
            justify-content: flex-start;
        }
    }
    @media (max-width: 767px) {
        .beta-event-meta-row {
            padding: 10px 12px;
        }
        .beta-meta-group {
            flex-basis: 100%;
            align-items: flex-start;
            gap: 8px;
            padding-right: 0;
        }
        .beta-meta-item + .beta-meta-item {
            margin-left: 10px;
            padding-left: 10px;
        }
    }
    .beta-tabs-container {
        position: relative;
        padding-top: 0;
    }
    .beta-tabs {
        margin-top: 0;
        margin-bottom: 0;
        display: flex;
        gap: 0;
        padding: 0;
        background: transparent;
        box-shadow: none;
    }
    .beta-tabs > li {
        margin-bottom: -1px;
    }
    .beta-tabs > li + li {
        margin-left: -1px;
    }
    .beta-tabs > li > a {
        padding: 11px 18px;
        font-weight: 600;
        color: #5a6775;
        border: 1px solid #cfd9e4;
        border-radius: 8px 8px 0 0;
        background: linear-gradient(180deg, #ffffff 0%, #edf2f7 100%);
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.7), 0 1px 0 rgba(215, 222, 231, 0.8);
        transition: background-color 0.15s ease, color 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease;
    }
    .beta-tabs > li > a:hover,
    .beta-tabs > li > a:focus {
        color: #334154;
        background: linear-gradient(180deg, #f9fbfd 0%, #f1f5f9 100%);
        border-color: #bfcddb;
    }
    .beta-tabs > li.active > a,
    .beta-tabs > li.active > a:hover,
    .beta-tabs > li.active > a:focus {
        position: relative;
        z-index: 2;
        margin-left: 0;
        color: #234d7d;
        background: linear-gradient(180deg, #ffffff 0%, #f9fbff 100%);
        border: 1px solid #d7dee7;
        border-bottom-color: #fff;
        box-shadow: 0 -1px 0 #62aaf6 inset, 0 2px 6px rgba(80, 108, 140, 0.08);
    }
    .beta-tab-content {
        background: #fff;
        border: 1px solid #d7dee7;
        border-top: none;
        margin-top: -2px;
        padding: 14px 20px 20px;
        border-radius: 0 8px 8px 8px;
        box-shadow: 0 1px 3px rgba(60, 78, 102, 0.04);
    }
    .beta-bulk-actions-bar {
        display: none;
        padding: 10px 14px;
        border: 1px solid #d9e5f2;
        border-radius: 8px 8px 0 0;
        background: linear-gradient(180deg, #f8fbff 0%, #eef5fc 100%);
        position: fixed;
        left: 24px;
        right: 24px;
        bottom: 0;
        z-index: 1100;
        box-shadow: 0 -4px 16px rgba(80, 108, 140, 0.14);
    }
    .beta-bulk-actions-bar.is-visible {
        display: block;
    }
    body.beta-bulk-actions-visible {
        padding-bottom: 84px;
    }
    .beta-bulk-actions-bar-inner {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
    }
    .beta-bulk-actions-summary {
        font-size: 13px;
        font-weight: 600;
        color: #36506b;
    }
    .beta-bulk-actions-buttons {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
        justify-content: flex-end;
        flex: 1 1 auto;
    }
    .beta-bulk-actions-buttons .btn {
        display: inline-flex;
        align-items: center;
        gap: 6px;
    }
    .beta-bulk-actions-group {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
    }
    .beta-bulk-actions-group.beta-bulk-actions-group-danger {
        margin-left: auto;
    }
    .beta-bulk-menu-wrap {
        position: relative;
    }
    .beta-bulk-menu-trigger {
        min-width: 104px;
        justify-content: center;
    }
    .beta-bulk-menu {
        display: none;
        position: absolute;
        right: 0;
        bottom: calc(100% + 8px);
        z-index: 1200;
        min-width: 160px;
        background: #fff;
        border: 1px solid #d7dee7;
        border-radius: 6px;
        box-shadow: 0 8px 18px rgba(80, 108, 140, 0.18);
        padding: 6px 0;
    }
    .beta-bulk-menu.is-open {
        display: block;
    }
    .beta-bulk-menu button {
        display: flex;
        width: 100%;
        align-items: center;
        gap: 8px;
        border: 0;
        background: transparent;
        padding: 8px 14px;
        font-size: 13px;
        color: #36506b;
        text-align: left;
    }
    .beta-bulk-menu button:hover,
    .beta-bulk-menu button:focus {
        background: #f5f8fc;
        color: #1d3550;
        outline: none;
    }
    @media (max-width: 767px) {
        .beta-bulk-actions-bar {
            left: 12px;
            right: 12px;
            bottom: 0;
            padding-bottom: calc(10px + env(safe-area-inset-bottom, 0px));
        }
        .beta-bulk-actions-bar-inner {
            flex-direction: column;
            align-items: stretch;
        }
        .beta-bulk-actions-buttons {
            justify-content: stretch;
        }
        .beta-bulk-actions-group {
            width: 100%;
        }
        .beta-bulk-actions-group.beta-bulk-actions-group-danger {
            margin-left: 0;
        }
        .beta-bulk-actions-buttons .btn {
            justify-content: center;
            flex: 1 1 auto;
        }
        .beta-bulk-menu-wrap {
            flex: 1 1 auto;
        }
        .beta-bulk-menu-trigger {
            width: 100%;
        }
        .beta-bulk-menu {
            left: 0;
            right: 0;
            min-width: 0;
        }
        body.beta-bulk-actions-visible {
            padding-bottom: 132px;
        }
    }
    .beta-card {
        background: #fff;
        border: 1px solid #e0e0e0;
        border-radius: 4px;
        margin-bottom: 20px;
        box-shadow: 0 6px 14px rgba(78, 104, 136, 0.11), 0 1px 2px rgba(78, 104, 136, 0.08);
    }
    .beta-card-accent {
        border-left-width: 4px;
    }
    .beta-card-accent .beta-card-header {
        background: transparent;
    }
    .beta-card-accent-preview {
        border-color: #d8e8fb;
        border-left-color: #62aaf6;
        background: linear-gradient(180deg, #fbfdff 0%, #f3f8ff 100%);
    }
    .beta-card-accent-preview .beta-card-header {
        color: #234d7d;
        border-bottom-color: #dce8f5;
    }
    .beta-card-accent-comments {
        border-color: #d7e9e6;
        border-left-color: #4fa7a0;
        background: linear-gradient(180deg, #fbfefd 0%, #eef8f6 100%);
    }
    .beta-card-accent-comments .beta-card-header {
        color: #2e6d68;
        border-bottom-color: #d6e8e5;
    }
    .beta-card-accent-reports {
        border-color: #d8e8fb;
        border-left-color: #62aaf6;
        background: linear-gradient(180deg, #fbfdff 0%, #f3f8ff 100%);
    }
    .beta-card-accent-reports .beta-card-header {
        color: #234d7d;
        border-bottom-color: #dce8f5;
    }
    .beta-card-header {
        padding: 10px 15px;
        border-bottom: 1px solid #f0f0f0;
        font-weight: 600;
        background-color: #fbfbfb;
    }
    .beta-card-body {
        padding: 15px;
    }
    .beta-correlation-org {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 2px 8px;
        border: 1px solid #d7e5f2;
        border-radius: 999px;
        background: #eff6fc;
        color: #2f5f87;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.02em;
        text-transform: uppercase;
    }
    .beta-correlation-org .fa {
        font-size: 10px;
    }
    .summary-report-preview-wrap {
        width: 100%;
    }
    .summary-report-expand-toggle {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 100%;
        height: 20px;
        margin-top: -1px;
        border: 1px solid #e0e0e0;
        border-top: 0;
        border-radius: 0 0 4px 4px;
        background: #f7f8f9;
        color: #6f7a83;
        text-decoration: none;
        cursor: pointer;
    }
    .summary-report-expand-toggle:hover,
    .summary-report-expand-toggle:focus {
        background: #eef2f5;
        color: #4f5b67;
        text-decoration: none;
    }
    .summary-report-expand-toggle .fa {
        font-size: 14px;
    }
    .beta-expandable-header {
        cursor: pointer;
        user-select: none;
    }
    .beta-expandable-header .fa {
        color: #7b8791;
    }
    .beta-header-count {
        color: #8a939c;
    }
    .beta-collections-header-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-top: 2px;
    }
    .beta-collections-header-actions {
        display: inline-flex;
        gap: 8px;
        align-items: center;
    }
    .beta-collections-header-left {
        display: inline-flex;
        align-items: center;
        gap: 8px;
    }
    .beta-context-section {
        margin-bottom: 14px;
        padding: 0;
        border: 0;
        border-radius: 0;
        background: transparent;
        filter: drop-shadow(0 6px 14px rgba(78, 104, 136, 0.11)) drop-shadow(0 1px 2px rgba(78, 104, 136, 0.07));
    }
    .beta-context-section:last-child {
        margin-bottom: 0;
    }
    .beta-context-section-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 0;
        padding: 10px 15px;
        border: 1px solid #e4ebf2;
        border-left-width: 5px;
        border-radius: 8px 8px 0 0;
        background: linear-gradient(180deg, #fdfefe 0%, #f3f7fb 100%);
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.8);
    }
    .beta-context-section-title {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        font-size: 14px;
        font-weight: 600;
        line-height: 1.42857143;
        color: #2f3a45;
    }
    .beta-context-section-body {
        min-width: 0;
        padding: 14px 14px 12px;
        border: 1px solid #e4ebf2;
        border-top: 0;
        border-radius: 0 0 8px 8px;
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.92) 0%, rgba(248, 250, 252, 0.96) 100%);
    }
    .beta-context-section-actions {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        flex-shrink: 0;
    }
    .beta-context-section-actions .addButton {
        margin-bottom: 0;
        min-height: 28px;
        padding: 4px 10px;
        line-height: 1.2;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border-radius: 4px;
    }
    .beta-context-section-actions .addButton .fa,
    .beta-context-section-actions .addButton .fas {
        line-height: 1;
    }
    .beta-event-report-empty-action {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
    }
    .beta-event-report-empty-action .btn {
        margin-bottom: 0;
        display: inline-flex;
        align-items: center;
    }
    .beta-event-report-empty-action .muted {
        margin: 0;
        line-height: 1.2;
    }
    .beta-context-section-collections {
        --beta-context-accent: #d79a45;
        --beta-context-border: #f2dfc0;
        --beta-context-ribbon-bg-1: #fffdf8;
        --beta-context-ribbon-bg-2: #fbf3e6;
        --beta-context-body-bg-1: rgba(255, 253, 248, 0.96);
        --beta-context-body-bg-2: rgba(251, 244, 232, 0.92);
    }
    .beta-context-section-collections .beta-context-section-title {
        color: #80511d;
    }
    .beta-context-section-tags {
        --beta-context-accent: #73b86a;
        --beta-context-border: #d8ead6;
        --beta-context-ribbon-bg-1: #fcfefb;
        --beta-context-ribbon-bg-2: #f1f9ef;
        --beta-context-body-bg-1: rgba(252, 254, 251, 0.96);
        --beta-context-body-bg-2: rgba(243, 250, 241, 0.92);
    }
    .beta-context-section-tags .beta-context-section-title {
        color: #2d5b2c;
    }
    .beta-context-section-galaxies {
        --beta-context-accent: #5f7dd8;
        --beta-context-border: #d9e2fb;
        --beta-context-ribbon-bg-1: #fcfdff;
        --beta-context-ribbon-bg-2: #eef3ff;
        --beta-context-body-bg-1: rgba(252, 253, 255, 0.96);
        --beta-context-body-bg-2: rgba(241, 245, 255, 0.92);
    }
    .beta-context-section-galaxies .beta-context-section-title {
        color: #3554a6;
    }
    .beta-context-section .beta-context-section-header {
        border-color: var(--beta-context-border);
        border-left-color: var(--beta-context-accent);
        background: linear-gradient(180deg, var(--beta-context-ribbon-bg-1) 0%, var(--beta-context-ribbon-bg-2) 100%);
    }
    .beta-context-section .beta-context-section-body {
        border-color: var(--beta-context-border);
        background: linear-gradient(180deg, var(--beta-context-body-bg-1) 0%, var(--beta-context-body-bg-2) 100%);
    }
    .beta-view-events .eventTagContainer .addButton,
    .beta-view-events .beta-context-section-actions .addButton {
        opacity: 0.6;
        transition: opacity 0.15s ease, filter 0.15s ease, box-shadow 0.15s ease;
    }
    .beta-view-events .eventTagContainer .tag-list-container .addButton {
        display: none !important;
    }
    .beta-view-events .eventTagContainer .addButton:hover,
    .beta-view-events .eventTagContainer .addButton:focus,
    .beta-view-events .beta-context-section-actions .addButton:hover,
    .beta-view-events .beta-context-section-actions .addButton:focus {
        opacity: 1;
        filter: brightness(1.08);
        box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.25) inset;
    }
    .beta-view-events .eventTagContainer .tag,
    .beta-view-events .eventTagContainer .tagFirstHalf,
    .beta-view-events .eventTagContainer .tagSecondHalf,
    .beta-view-events .eventTagContainer .tagComplete,
    .beta-view-events .eventTagContainer .tag-container .label,
    .beta-view-events .eventTagContainer .tag-list-container,
    .beta-view-events .eventTagContainer .tag-list-container a,
    .beta-view-events .eventTagContainer .tag-list-container span {
        font-family: inherit;
        font-size: 12px;
        letter-spacing: 0;
    }
    .beta-view-events .eventTagContainer .tag-container {
        filter: none;
    }
    .beta-view-events .eventTagContainer .tagFirstHalf,
    .beta-view-events .eventTagContainer .tagSecondHalf,
    .beta-view-events .eventTagContainer .tagComplete,
    .beta-view-events .eventTagContainer .tag {
        box-shadow: none;
        border: 1px solid rgba(74, 138, 214, 0.35);
    }
    .beta-view-events .eventTagContainer .tagFirstHalf,
    .beta-view-events .eventTagContainer .tag {
        background: #f8fbff;
        color: #33475b;
    }
    .beta-view-events .eventTagContainer .tagSecondHalf,
    .beta-view-events .eventTagContainer .tagComplete {
        background: #eef6ff;
        color: #31475d;
    }
    .beta-view-events #galaxies_div {
        position: static;
        padding: 0;
        background: transparent;
        border: 0;
        border-radius: 0;
        width: auto;
    }
    .beta-context-section-collections #event-collections-container,
    .beta-context-section-tags .eventTagContainer,
    .beta-context-section-galaxies #galaxies_div {
        display: block;
        width: 100%;
    }
    .beta-context-section-tags .eventTagContainer .tag-list-container {
        display: block;
        margin-right: 0;
    }
    .beta-view-events #galaxies_div > .title-section {
        position: static;
        padding: 0;
        border: 0;
        background: transparent;
    }
    .beta-correlations-container {
        display: flex;
        flex-direction: column;
        gap: 18px;
    }
    .correlation-event-card {
        margin-bottom: 0 !important;
        border: 1px solid #dfe7ef;
        border-left-width: 4px;
        border-radius: 8px;
        overflow: hidden;
        background: #fff;
        box-shadow: 0 1px 2px rgba(31, 45, 61, 0.04);
    }
    .correlation-event-card .beta-card-header {
        padding: 12px 18px;
        border-bottom: 1px solid #e7edf3;
        background: linear-gradient(180deg, #f9fbfd 0%, #f3f7fb 100%) !important;
    }
    .correlation-event-card .beta-card-body {
        padding: 0;
    }
    .beta-correlation-org {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        border: 1px solid #dce6f0;
        border-radius: 999px;
        background: #f6f9fc;
        color: #46627c;
        font-size: 12px;
        font-weight: 600;
    }
    .beta-correlation-event-link {
        color: #167cc5;
        font-weight: 700;
        font-size: 16px;
        text-decoration: none;
    }
    .beta-correlation-event-link:hover,
    .beta-correlation-event-link:focus {
        color: #0c68a9;
        text-decoration: none;
    }
    .beta-correlation-row {
        background: #fff;
    }
    .beta-correlation-row td {
        padding-top: 14px;
        padding-bottom: 14px;
        border-top: 1px solid #edf2f6;
        vertical-align: top;
    }
    .beta-correlation-row:first-child td {
        border-top: 0;
    }
    .beta-correlation-anchor-cell {
        width: 44px;
        text-align: center;
        color: #c2cbd4;
    }
    .beta-correlation-meta {
        display: flex;
        flex-direction: column;
        gap: 6px;
    }
    .beta-correlation-chevrons {
        display: inline-flex;
        align-items: stretch;
        flex-wrap: wrap;
        overflow: hidden;
        border-radius: 999px;
    }
    .beta-correlation-chevron {
        position: relative;
        display: inline-flex;
        align-items: center;
        min-height: 26px;
        padding: 0 13px 0 16px;
        border: 1px solid transparent;
        border-radius: 0;
        font-size: 10px;
        font-weight: 600;
        line-height: 1;
        white-space: nowrap;
    }
    .beta-correlation-chevron::after {
        content: '';
        position: absolute;
        top: -1px;
        right: -14px;
        width: 28px;
        height: 28px;
        background: inherit;
        border-top: 1px solid currentColor;
        border-right: 1px solid currentColor;
        transform: rotate(45deg) scale(0.71);
        transform-origin: center;
        z-index: 1;
    }
    .beta-correlation-chevron::before {
        content: '';
        position: absolute;
        top: -1px;
        left: -14px;
        width: 28px;
        height: 28px;
        background: #f3f6f9;
        border-top: 1px solid #d9e1e8;
        border-right: 1px solid #d9e1e8;
        transform: rotate(45deg) scale(0.71);
        transform-origin: center;
        z-index: 0;
    }
    .beta-correlation-chevron > span {
        position: relative;
        z-index: 2;
    }
    .beta-correlation-chevron:first-child {
        padding-left: 13px;
        border-top-left-radius: 999px;
        border-bottom-left-radius: 999px;
    }
    .beta-correlation-chevron:first-child::before {
        display: none;
    }
    .beta-correlation-chevron:last-child {
        padding-right: 13px;
        border-top-right-radius: 999px;
        border-bottom-right-radius: 999px;
    }
    .beta-correlation-chevron:last-child::after {
        display: none;
    }
    .beta-correlation-chevron.beta-correlation-category {
        background: #f3f6f9;
        border-color: #d9e1e8;
        color: #8b99a6;
    }
    .beta-correlation-chevron.beta-correlation-relation {
        background: #edf4fb;
        border-color: #d1e1f0;
        color: #5c7fa2;
    }
    .beta-correlation-chevron.beta-correlation-type {
        background: #f4f7fb;
        border-color: #d6e0ea;
        color: #566575;
    }
    .beta-correlation-comment-inline {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        min-height: 24px;
        max-width: min(100%, 520px);
        padding: 3px 10px;
        border: 1px solid #dbe5ef;
        border-radius: 999px;
        background: #ffffff;
        color: #667686;
        font-size: 11px;
        font-weight: 500;
        line-height: 1.35;
        overflow-wrap: anywhere;
        box-shadow: 0 1px 2px rgba(31, 57, 83, 0.05), inset 0 1px 0 rgba(255, 255, 255, 0.8);
    }
    .beta-correlation-comment-inline span {
        min-width: 0;
    }
    .beta-correlation-comment-inline .fa,
    .beta-correlation-comment-inline .fas {
        flex: 0 0 auto;
        color: #7d91a4;
        font-size: 10px;
        opacity: 0.95;
    }
    .beta-correlation-filter-comments {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 8px;
        margin: 0 0 10px;
        color: #c96b11;
        font-size: 13px;
        line-height: 1.5;
    }
    .beta-correlation-filter-comments:empty {
        display: none;
    }
    .beta-correlation-filter-comments-label {
        flex: 0 0 auto;
        font-size: 13px;
        font-weight: 500;
        color: #ff6f00;
    }
    .beta-correlation-filter-comment-chip {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        max-width: 100%;
        padding: 6px 12px;
        border: 1px solid #c7d7e8;
        border-radius: 999px;
        background: #fff;
        color: #4f6478;
        font-size: 13px;
        line-height: 1.4;
        cursor: pointer;
        text-align: left;
    }
    .beta-correlation-filter-comment-chip:hover,
    .beta-correlation-filter-comment-chip:focus {
        color: #2f4b67;
        border-color: #9fb7d1;
        text-decoration: none;
        outline: none;
        box-shadow: 0 0 0 2px rgba(66, 139, 202, 0.14);
    }
    .beta-correlation-filter-comment-chip i {
        flex: 0 0 auto;
        color: #7d91a4;
        font-size: 10px;
    }
    .beta-correlation-filter-comment-chip span {
        min-width: 0;
        white-space: normal;
        word-break: break-word;
    }
    .beta-correlation-value-row {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        min-width: 0;
    }
    .beta-correlation-value-link {
        color: #263443;
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 13px;
        text-decoration: none;
        overflow-wrap: anywhere;
    }
    .beta-correlation-value-link:hover,
    .beta-correlation-value-link:focus {
        color: #167cc5;
        text-decoration: none;
    }
    .beta-correlation-branch-link {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 16px;
        color: #5b8bb5;
        font-size: 11px;
        text-decoration: none;
    }
    .beta-correlation-branch-link:hover,
    .beta-correlation-branch-link:focus {
        color: #346f9d;
        text-decoration: none;
    }
    .beta-correlation-inline-tags {
        display: flex;
        flex-wrap: wrap;
        gap: 4px;
        margin-top: 4px;
        opacity: 0.5;
        transition: opacity 0.18s ease;
    }
    .beta-correlation-row:hover .beta-correlation-inline-tags {
        opacity: 1;
    }
    .beta-correlation-inline-tags .tag-container {
        filter: none;
    }
    .beta-correlation-inline-tags .tag,
    .beta-correlation-inline-tags .tagFirstHalf,
    .beta-correlation-inline-tags .tagSecondHalf,
    .beta-correlation-inline-tags .tagComplete,
    .beta-correlation-inline-tags .tag-container .label,
    .beta-correlation-inline-tags .tag-list-container,
    .beta-correlation-inline-tags .tag-list-container a,
    .beta-correlation-inline-tags .tag-list-container span {
        font-family: inherit;
        font-size: 12px;
        letter-spacing: 0;
    }
    .beta-correlation-inline-tags .tagFirstHalf,
    .beta-correlation-inline-tags .tagSecondHalf,
    .beta-correlation-inline-tags .tagComplete,
    .beta-correlation-inline-tags .tag {
        box-shadow: none;
        border: 1px solid rgba(74, 138, 214, 0.35);
    }
    .beta-correlation-inline-tags .tagFirstHalf,
    .beta-correlation-inline-tags .tag {
        background: #f8fbff;
        color: #33475b;
    }
    .beta-correlation-inline-tags .tagSecondHalf,
    .beta-correlation-inline-tags .tagComplete {
        background: #eef6ff;
        color: #31475d;
    }
    .beta-correlation-status-icon {
        color: #a8b4c0;
    }
    .beta-correlation-status-icon.is-ids-active {
        color: #b06f2f;
        opacity: 0.95;
    }
    .beta-correlation-status-icon.is-correlation-active {
        color: #6f8398;
        opacity: 0.95;
    }
    .beta-correlation-distribution-cell,
    .beta-correlation-date-cell {
        text-align: center;
    }
    .beta-correlation-date-text {
        font-size: 11px;
        color: #7e8b98;
        white-space: nowrap;
    }
    .comment-bullet-list {
        margin: 0;
        padding-left: 18px;
        list-style-type: disc;
    }
    .comment-bullet-item {
        margin: 0 0 8px 0;
        color: #2f2f2f;
    }
    .comment-bullet-action {
        display: inline-flex;
        align-items: center;
        gap: 12px;
        max-width: 100%;
        padding: 2px 0;
        border: 0;
        background: transparent;
        color: inherit;
        text-align: left;
        cursor: pointer;
    }
    .comment-bullet-action:hover .comment-bullet-label,
    .comment-bullet-action:hover .comment-bullet-count,
    .comment-bullet-action:focus .comment-bullet-label,
    .comment-bullet-action:focus .comment-bullet-count {
        color: #0b6a9b;
    }
    .comment-bullet-action:focus {
        outline: none;
    }
    .comment-bullet-action:focus-visible {
        border-radius: 999px;
        box-shadow: 0 0 0 2px rgba(11, 106, 155, 0.18);
    }
    .comment-bullet-label {
        font-size: 14px;
        min-width: 0;
    }
    .comment-bullet-count {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 28px;
        margin-left: 2px;
        padding: 2px 8px;
        border: 1px solid #c9d6e2;
        border-radius: 999px;
        background: #f4f8fb;
        font-size: 12px;
        font-weight: 700;
        color: #34546f;
        line-height: 1.2;
        white-space: nowrap;
    }
    .composition-singlebar-wrap {
        width: 100%;
    }
    .beta-composition-row {
        display: flex;
        align-items: center;
        gap: 14px;
        margin-bottom: 0;
        padding: 10px 14px 12px;
        border: 0;
        border-bottom: 1px solid rgba(123, 145, 175, 0.16);
        border-radius: 0;
        background: transparent;
    }
    .beta-attributes-top-panel {
        margin-bottom: 18px;
        border: 1px solid #d7e2ef;
        border-radius: 10px;
        background: linear-gradient(180deg, #f7f9fd 0%, #eef4fb 100%);
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.8);
    }
    .beta-attributes-top-panel .beta-attributes-list {
        padding: 0 14px 14px;
    }
    .beta-attributes-top-panel .beta-attr-toolbar {
        padding-top: 12px;
    }
    .beta-attributes-top-panel .beta-attr-table {
        border-top: 1px solid #dce6f1;
    }
    .beta-composition-label {
        flex: 0 0 auto;
        font-size: 13px;
        font-weight: 700;
        color: #526579;
        white-space: nowrap;
    }
    .beta-composition-row .composition-singlebar-wrap {
        flex: 1 1 auto;
        min-width: 0;
    }
    .composition-singlebar {
        width: 100%;
        height: 24px;
        border-radius: 6px;
        overflow: hidden;
        border: 1px solid #d7dfe8;
        background: #f7f9fc;
        display: flex;
    }
    .composition-singlebar .segment {
        height: 100%;
        min-width: 1px;
        cursor: pointer;
        transition: opacity 0.15s ease;
    }
    .composition-singlebar .segment:hover {
        opacity: 0.82;
    }
    .composition-label-grid {
        margin-top: 8px;
    }
    .composition-label-list {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        align-items: center;
    }
    .composition-label-chip {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        line-height: 1.2;
        color: #3c4854;
        border: 1px solid #d7dfe8;
        border-radius: 12px;
        padding: 3px 8px;
        background: #fbfdff;
        cursor: pointer;
        user-select: none;
    }
    .composition-label-chip:hover {
        background: #f0f6ff;
        border-color: #c2d2e6;
    }
    .composition-label-chip .swatch {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        flex: 0 0 8px;
    }
    .composition-label-chip strong {
        color: #26313d;
    }
    .composition-inline-label {
        font-size: 11px;
        font-weight: 600;
        fill: #ffffff;
        text-shadow: 0 1px 1px rgba(0, 0, 0, 0.35);
        pointer-events: none;
    }
    /* Toggle Switch */
    .switch {
        position: relative;
        display: inline-block;
        width: 40px;
        height: 20px;
        vertical-align: middle;
    }
    .switch input { 
        opacity: 0;
        width: 0;
        height: 0;
    }
    .slider {
        position: absolute;
        cursor: pointer;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: #ccc;
        -webkit-transition: .4s;
        transition: .4s;
        border-radius: 20px;
    }
    .slider:before {
        position: absolute;
        content: "";
        height: 16px;
        width: 16px;
        left: 2px;
        bottom: 2px;
        background-color: white;
        -webkit-transition: .4s;
        transition: .4s;
        border-radius: 50%;
    }
    input:checked + .slider {
        background-color: #428bca;
    }
    input:focus + .slider {
        box-shadow: 0 0 1px #428bca;
    }
    input:checked + .slider:before {
        -webkit-transform: translateX(20px);
        -ms-transform: translateX(20px);
        transform: translateX(20px);
    }
    .publish-box .meta-value {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .edit-box .meta-value {
        display: flex;
        align-items: center;
    }
    .published-label {
        font-weight: 700;
        font-size: 12px;
        line-height: 1;
    }
    .published-label.state-published {
        color: #2f8f46;
    }
    .published-label.state-unpublished {
        color: #c0392b;
    }


    /* Common Beta UI Styles */
    .beta-toolbar {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 15px;
    }
    .beta-attr-table {
        width: 100%;
        border-collapse: separate; 
        border-spacing: 0;
        margin-top: 10px;
        table-layout: fixed;
    }
    .beta-attr-table th {
        text-align: left;
        padding: 12px 10px;
        border-bottom: 2px solid #eee;
        color: #777;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .beta-attr-table td {
        padding: 8px 10px;
        border-bottom: 1px solid #f9f9f9;
        vertical-align: top;
        font-size: 13px;
    }
    .beta-attr-row:hover {
        background-color: #f5f5f5;
    }
    .beta-row-actions {
        display: inline-flex;
        align-items: center;
        gap: 0;
        position: relative;
        height: 24px;
        border: 1px solid #dee2e6;
        border-radius: 4px;
        background: #fff;
        overflow: hidden;
    }
    .beta-row-actions input[type="checkbox"] {
        margin: 0 4px;
    }
    .beta-row-menu-trigger {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 20px;
        height: 100%;
        cursor: pointer;
        padding: 0;
        border-left: 1px solid #dee2e6;
        color: #777;
        transition: background 0.2s, color 0.2s;
    }
    .beta-row-menu-trigger:hover {
        background: #f8f9fa;
        color: #333;
    }
    .beta-row-menu {
        display: none;
        position: absolute;
        z-index: 10000;
        background: white;
        border: 1px solid #ddd;
        border-radius: 4px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        min-width: 160px;
        padding: 5px 0;
        right: 0;
        top: 100%;
    }
    .beta-row-menu.active-moved {
        right: auto;
        width: max-content;
        max-width: 320px;
    }
    .beta-row-menu ul {
        list-style: none;
        padding: 0;
        margin: 0;
    }
    .beta-row-menu li a {
        display: block;
        padding: 8px 15px;
        color: #444;
        text-decoration: none;
        font-size: 13px;
    }
    .beta-row-menu li a:hover {
        background-color: #f5f5f5;
        color: #000;
    }
    .beta-row-menu .divider {
        height: 1px;
        background: #eee;
        margin: 5px 0;
    }
    .beta-uuid-compact {
        font-size: 10px;
        color: #bbb;
        cursor: pointer;
        font-family: monospace;
    }
    .beta-uuid-compact:hover {
        color: #428bca;
        text-decoration: underline;
    }
    @media (max-width: 767px) {
        .beta-composition-row {
            flex-direction: column;
            align-items: stretch;
            gap: 8px;
        }
        .beta-attributes-top-panel .beta-attributes-list {
            padding: 0 12px 12px;
        }
        .beta-event-header-row {
            align-items: stretch;
        }
        .beta-event-metadata-panel {
            flex-basis: 100%;
            width: 100%;
            border-radius: 10px 10px 0 0;
        }
        .beta-event-header-actions {
            justify-content: flex-start;
        }
        .beta-event-subtitle {
            justify-content: flex-start;
        }
        .beta-event-meta-row {
            border-radius: 0 0 10px 10px;
        }
    }
    .beta-tags-container {
        display: flex;
        flex-wrap: wrap;
        gap: 5px;
    }
    .beta-relative-timestamp {
        font-size: 12px;
        color: #666;
        cursor: pointer;
    }
    .beta-relative-timestamp:hover {
        text-decoration: underline;
    }
    .beta-attr-meta-block {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    .beta-attr-type-path {
        font-size: 11px;
        color: #888;
        display: flex;
        align-items: center;
        gap: 6px;
        margin-bottom: 2px;
    }
    .beta-category-label {
        font-size: 10px;
        color: #aaa;
        text-transform: uppercase;
        letter-spacing: 0.3px;
    }
    .beta-type-insight {
        background: #f0f0f0;
        padding: 1px 6px;
        border-radius: 10px;
        font-weight: 600;
        color: #444;
        border: 1px solid #e0e0e0;
    }
    .beta-object-relation-insight {
        background: #e8f4fd;
        padding: 1px 6px;
        border-radius: 10px;
        font-weight: 600;
        color: #2f5a93;
        border: 1px solid #d1e9f5;
    }
    .beta-deeplink-highlight {
        background-color: #ffe9a3;
        box-shadow: inset 0 0 0 1px #e2bd4f;
    }
    .beta-deeplink-highlight td {
        background-color: #ffe9a3 !important;
    }
    .report-snippet {
        font-family: inherit;
        line-height: 1.4;
    }
    .report-name-cell:hover {
        text-decoration: underline;
    }
    .beta-warninglist-table thead th {
        position: static;
        top: auto;
        z-index: auto;
    }
    .beta-warninglist-table thead th::after {
        display: none;
    }
</style>

<div class="events view beta-view-events">
    <!-- Header -->
    <div class="beta-header-container">
        <div class="beta-event-header-row">
            <div class="beta-event-metadata-panel">
                <h2 class="beta-event-title">
                    <?php echo h($event['Event']['info']); ?>
                </h2>
                <div class="beta-event-subtitle">
                    <div class="beta-event-subtitle-chips">
                        <span class="beta-id-badge">
                            <span class="beta-id-badge-label"><?php echo __('ID'); ?></span>
                            <span class="beta-id-badge-value"><?php echo h($event['Event']['id']); ?></span>
                        </span>
                        <span class="beta-id-badge">
                            <span class="beta-id-badge-label"><?php echo __('UUID'); ?></span>
                            <span class="beta-id-badge-value"><?php echo h($event['Event']['uuid']); ?></span>
                        </span>
                    </div>
                    <div class="beta-event-header-actions">
                        <?php if ($this->Acl->canPublishEvent($event)): ?>
                            <label class="beta-event-header-control is-publish is-interactive" title="<?php echo __('Toggle publication status'); ?>">
                                <i class="fa fa-bullhorn"></i>
                                <span id="publishedLabel" class="published-label <?php echo !empty($event['Event']['published']) ? 'state-published' : 'state-unpublished'; ?>"><?php echo !empty($event['Event']['published']) ? __('Published') : __('Unpublished'); ?></span>
                                <span class="switch">
                                    <input type="checkbox" id="publishedToggle" data-id="<?php echo h($event['Event']['id']); ?>" <?php echo $event['Event']['published'] ? 'checked' : ''; ?>>
                                    <span class="slider round"></span>
                                </span>
                            </label>
                        <?php else: ?>
                            <span class="beta-event-header-control is-publish" title="<?php echo __('Publication status'); ?>">
                                <i class="fa fa-bullhorn"></i>
                                <span id="publishedLabel" class="published-label <?php echo !empty($event['Event']['published']) ? 'state-published' : 'state-unpublished'; ?>"><?php echo !empty($event['Event']['published']) ? __('Published') : __('Unpublished'); ?></span>
                            </span>
                        <?php endif; ?>
                        <?php if ($this->Acl->canModifyEvent($event)): ?>
                            <a href="<?php echo $baseurl; ?>/events/edit/<?php echo h($event['Event']['id']); ?>" class="beta-event-header-control beta-event-header-control-link" title="<?php echo __('Edit event header'); ?>">
                                <i class="fa fa-edit"></i>
                                <span><?php echo __('Edit event header'); ?></span>
                            </a>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
        <div class="beta-event-meta-row">
            <?php
                $creatorUser = '';
                if (!empty($event['User']['email'])) {
                    $creatorUser = $event['User']['email'];
                } elseif (!empty($event['User']['id'])) {
                    $creatorUser = __('User #%s', $event['User']['id']);
                } elseif (!empty($event['Event']['user_id'])) {
                    $creatorUser = __('User #%s', $event['Event']['user_id']);
                }
            ?>
            <div class="beta-meta-group">
                <div class="beta-meta-group-title" title="<?php echo __('When'); ?>"><i class="fa fa-calendar"></i></div>
                <div class="beta-meta-items">
                    <div class="beta-meta-item">
                        <span class="beta-meta-item-label"><?php echo __('Date'); ?></span>
                        <span class="beta-meta-item-value"><?php echo h($event['Event']['date']); ?></span>
                    </div>
                    <div class="beta-meta-item">
                        <span class="beta-meta-item-label"><?php echo __('Updated'); ?></span>
                        <span class="beta-meta-item-value beta-relative-timestamp"
                            data-timestamp="<?= h($event['Event']['timestamp']) ?>"
                            data-absolute="<?= h(date('Y-m-d H:i:s', $event['Event']['timestamp'])) ?>"
                            title="<?= h(date('Y-m-d H:i:s', $event['Event']['timestamp'])) ?> (click to copy)"
                            style="cursor: pointer;">
                            <?php echo $this->Time->time($event['Event']['timestamp']); ?>
                        </span>
                    </div>
                </div>
            </div>
            <div class="beta-meta-group">
                <div class="beta-meta-group-title" title="<?php echo __('Who'); ?>"><i class="fa fa-users"></i></div>
                <div class="beta-meta-items">
                    <div class="beta-meta-item">
                        <span class="beta-meta-item-label"><?php echo __('Creator'); ?></span>
                        <span class="beta-meta-item-value">
                            <a href="<?= $baseurl ?>/organisations/view/<?= (int)$event['Orgc']['id'] ?>" class="beta-meta-org-link" title="<?= h($event['Orgc']['name']) ?>">
                                <img
                                    src="<?= $baseurl ?>/organisations/getOrgLogo/<?= h($event['Orgc']['id']) ?>.json"
                                    title="<?= h($event['Orgc']['name']) ?>"
                                    alt="<?= h($event['Orgc']['name']) ?>"
                                    width="20"
                                    height="20"
                                    onerror="this.onerror=null; this.remove();"
                                >
                                <span><?= h($event['Orgc']['name']) ?></span>
                            </a>
                        </span>
                    </div>
                    <div class="beta-meta-item">
                        <span class="beta-meta-item-label"><?php echo __('Owner'); ?></span>
                        <span class="beta-meta-item-value">
                            <a href="<?= $baseurl ?>/organisations/view/<?= (int)$event['Org']['id'] ?>" class="beta-meta-org-link" title="<?= h($event['Org']['name']) ?>">
                                <img
                                    src="<?= $baseurl ?>/organisations/getOrgLogo/<?= h($event['Org']['id']) ?>.json"
                                    title="<?= h($event['Org']['name']) ?>"
                                    alt="<?= h($event['Org']['name']) ?>"
                                    width="20"
                                    height="20"
                                    onerror="this.onerror=null; this.remove();"
                                >
                                <span><?= h($event['Org']['name']) ?></span>
                            </a>
                        </span>
                    </div>
                    <div class="beta-meta-item">
                        <span class="beta-meta-item-label"><?php echo __('User'); ?></span>
                        <span class="beta-meta-item-value<?php echo empty($creatorUser) ? ' muted' : ''; ?>">
                            <?php echo !empty($creatorUser) ? h($creatorUser) : __('Unknown'); ?>
                        </span>
                    </div>
                </div>
            </div>
            <div class="beta-meta-group beta-meta-group-scope">
                <div class="beta-meta-group-title" title="<?php echo __('Scope'); ?>"></div>
                <div class="beta-meta-items">
                    <div class="beta-meta-item" title="<?php echo h($distributionLevels[$event['Event']['distribution']]); ?>">
                        <span class="beta-meta-item-label"><?php echo __('Distribution'); ?></span>
                        <span class="beta-meta-item-value beta-meta-item-value-inline">
                            <div class="dist-widget dist-<?= intval($event['Event']['distribution']) ?> distributionNetworkToggle"
                                 title="<?= $event['Event']['distribution'] == 4 ? h($event['SharingGroup']['name']) : h($distributionLevels[$event['Event']['distribution']]) ?>"
                                 data-event-distribution="<?= intval($event['Event']['distribution']) ?>"
                                 data-event-distribution-name="<?= $event['Event']['distribution'] == 4 ? h($event['SharingGroup']['name']) : h($shortDist[$event['Event']['distribution']]) ?>"
                                 data-scope-id="<?= h($event['Event']['id']) ?>">
                                <i class="fa fa-share-alt" aria-hidden="true"></i>
                            </div>
                            <?php 
                                if ($event['Event']['distribution'] == 4):
                                    echo $this->Html->link($event['SharingGroup']['name'], array('controller' => 'sharing_groups', 'action' => 'view', $event['SharingGroup']['id']));
                                else:
                                    echo h($shortDist[$event['Event']['distribution']]);
                                endif;
                            ?>
                        </span>
                    </div>
                </div>
            </div>
        </div>
        
        <?php if (!empty($warnings)): ?>
            <div class="alert alert-warning beta-alert" style="margin-top: 15px;">
                 <?php if (is_array($warnings)): ?>
                    <?php
                        foreach ($warnings as $k => $warning) {
                            if (is_array($warning)) {
                                $warnings[$k] = implode('<br>', $warning);
                            }
                        }
                        echo implode('<br>', $warnings);
                    ?>
                <?php else: ?>
                    <?php echo $warnings; ?>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

    <!-- Tabs -->
    <?php
    // Prepare items
    $items = [];
    
    if (!empty($event['objects'])) {
        $items = [];
        $objectAttributeIds = [];
        foreach ($event['objects'] as $item) {
            if ($item['objectType'] === 'object') {
                if (!empty($item['Attribute'])) {
                    foreach ($item['Attribute'] as $objAttr) {
                        $objectAttributeIds[$objAttr['id']] = true;
                    }
                }
            }
        }
        foreach ($event['objects'] as $item) {
            if ($item['objectType'] === 'attribute' && isset($objectAttributeIds[$item['id']])) {
                continue;
            }
            $items[] = $item;
        }
    } else {
        $objectAttributeIds = [];
        if (!empty($event['Object'])) {
            foreach ($event['Object'] as $obj) {
                if (!empty($obj['Attribute'])) {
                    foreach ($obj['Attribute'] as $objAttr) {
                        $objectAttributeIds[$objAttr['id']] = true;
                    }
                }
            }
        }

        if (!empty($event['Attribute'])) {
            foreach ($event['Attribute'] as $attr) {
                if (isset($objectAttributeIds[$attr['id']])) {
                    continue;
                }
                $attr['objectType'] = 'attribute';
                $items[] = $attr;
            }
        }
        if (!empty($event['Object'])) {
            foreach ($event['Object'] as $obj) {
                $obj['objectType'] = 'object';
                $items[] = $obj;
            }
        }
    }

    $items = $this->Event->attachRelatedAttributesToItems($items, $event['RelatedAttribute'] ?? []);

    // Sort desc by timestamp
    usort($items, function($a, $b) {
        return $b['timestamp'] - $a['timestamp'];
    });

    // Server-side pagination params from CustomPaginationTool
    $paging = isset($this->params->params['paging']['Event']) ? $this->params->params['paging']['Event'] : [];
    $betaCurrentPage = isset($paging['page']) ? (int)$paging['page'] : 1;
    $betaPageSize = isset($paging['limit']) ? (int)$paging['limit'] : 50;
    $betaTotalItems = isset($paging['count']) ? (int)$paging['count'] : 0;
    $betaTotalPages = isset($paging['pageCount']) ? (int)$paging['pageCount'] : 1;

    // Count total items for display purposes
    $betaTotalAttributes = $betaTotalItems > 0 ? $betaTotalItems : count($items);

    // Calculate display range for "Showing X-Y of Z"
    $betaShowStart = ($betaCurrentPage - 1) * $betaPageSize + 1;
    $betaShowEnd = min($betaCurrentPage * $betaPageSize, $betaTotalItems);
    if ($betaTotalItems == 0) {
        $betaShowStart = 0;
        $betaShowEnd = 0;
    }
    $eventReportSummary = isset($eventReportSummary) && is_array($eventReportSummary) ? $eventReportSummary : [];
    $firstEventReportId = $eventReportSummary['id'] ?? null;
    $firstEventReportMarkdown = $eventReportSummary['markdown'] ?? null;
    $eventReportCount = isset($eventReportSummary['count'])
        ? (int)$eventReportSummary['count']
        : (isset($event['Event']['report_count']) ? (int)$event['Event']['report_count'] : 0);
    $canModifyEvent = $this->Acl->canModifyEvent($event);
    $bulkAttributePermissions = [
        'edit' => $canModifyEvent && $this->Acl->canAccess('attributes', 'editSelected'),
        'tagGlobal' => $this->Acl->canAccess('attributes', 'addTag') && $this->Acl->canModifyTag($event),
        'tagLocal' => $this->Acl->canAccess('attributes', 'addTag') && $this->Acl->canModifyTag($event, true),
        'galaxyGlobal' => $this->Acl->canAccess('galaxies', 'selectGalaxyNamespace') && $this->Acl->canModifyTag($event),
        'galaxyLocal' => $this->Acl->canAccess('galaxies', 'selectGalaxyNamespace') && $this->Acl->canModifyTag($event, true),
        'groupIntoObject' => $canModifyEvent && $this->Acl->canAccess('objects', 'proposeObjectsFromAttributes'),
        'addRelationships' => $canModifyEvent && $this->Acl->canAccess('objectReferences', 'bulkAdd'),
        'sightings' => $this->Acl->canAccess('sightings', 'advanced'),
        'delete' => $canModifyEvent && $this->Acl->canAccess('attributes', 'deleteSelected'),
    ];
    $hasBulkAttributePermissions = isset($hasBulkAttributePermissions)
        ? (bool)$hasBulkAttributePermissions
        : in_array(true, $bulkAttributePermissions, true);
    ?>
    <div class="beta-tabs-container">
        <ul class="nav nav-tabs beta-tabs" role="tablist">
            <li role="presentation" class="active"><a href="#summary" aria-controls="summary" role="tab" data-toggle="tab"><?php echo __('Summary'); ?></a></li>
            <li role="presentation"><a href="#attributes" aria-controls="attributes" role="tab" data-toggle="tab"><?php echo __('Data'); ?> (<?php echo h($betaTotalAttributes); ?>)</a></li>
            <li role="presentation"><a href="#correlations" aria-controls="correlations" role="tab" data-toggle="tab"><?php echo __('Correlations'); ?> (<?php echo isset($relatedEventCorrelationCount) ? count($relatedEventCorrelationCount) : 0; ?>)</a></li>
            <li role="presentation"><a href="#history" aria-controls="history" role="tab" data-toggle="tab"><?php echo __('History'); ?></a></li>
        </ul>

        <div class="tab-content beta-tab-content">
            <!-- Summary Tab -->
            <div role="tabpanel" class="tab-pane active" id="summary">
                 <div class="row-fluid">
                     <div class="span8">
                         <!-- Report Snippet -->
                           <div class="beta-card summary-card beta-card-accent beta-card-accent-preview">
                               <div class="beta-card-header"><?php echo __('Event report'); ?></div>
                               <div class="beta-card-body">
                                  <?php if (!empty($firstEventReportMarkdown)): ?>
                                        <div class="summary-report-preview-wrap">
                                        <iframe id="summary-report-iframe"
                                            src="<?php echo $baseurl; ?>/eventReports/viewRendered/<?php echo h($firstEventReportId); ?>"
                                            style="width: 100%; min-height: 120px; border: 1px solid #e0e0e0; border-radius: 4px 4px 0 0; background: #fff; overflow: hidden;"
                                            frameborder="0"
                                            scrolling="auto"
                                            sandbox="allow-same-origin allow-scripts allow-popups allow-forms"
                                            loading="lazy"></iframe>
                                            <a href="#" id="summary-report-expand-toggle" class="summary-report-expand-toggle" onclick="toggleReportPreviewSize(); return false;" data-expand-label="<?php echo h(__('Expand preview')); ?>" data-collapse-label="<?php echo h(__('Collapse preview')); ?>" aria-label="<?php echo h(__('Expand preview')); ?>" title="<?php echo h(__('Expand preview')); ?>">
                                                <i id="summary-report-expand-icon" class="fa fa-angle-double-down" aria-hidden="true"></i>
                                            </a>
                                        </div>
                                          <div style="margin-top: 10px;">
                                              <a href="#" onclick="viewFullReport(<?php echo h($firstEventReportId); ?>); return false;"><?php echo __('View full report'); ?></a>
                                              |
                                              <a href="#summary-reports-section" onclick="toggleSummaryReports(true); document.getElementById('summary-reports-section').scrollIntoView({behavior: 'smooth', block: 'start'}); return false;"><?php echo __('See all reports'); ?></a>
                                           </div>
                                    <?php else: ?>
                                        <?php if ((int)$eventReportCount === 0 && $this->Acl->canAccess('eventReports', 'add') && $this->Acl->canModifyEvent($event)): ?>
                                            <div class="beta-event-report-empty-action">
                                                <a href="<?php echo $baseurl; ?>/eventReports/add/<?php echo h($event['Event']['id']); ?>" class="btn btn-link modal-open" style="padding-left: 0;" title="<?php echo __('Add Event Report'); ?>">
                                                    <i class="fa fa-plus"></i> <?php echo __('Add an event report'); ?>
                                                </a>
                                                <span class="muted"><?php echo __('(Good events always have a report to explain context!)'); ?></span>
                                            </div>
                                        <?php endif; ?>
                                    <?php endif; ?>

                                  <!-- Analysis Links Sub-section -->
                                  <?php
                                      $analysisLinks = [];
                                      $seenIds = [];
                                      $extractFromAttributes = function($attributes) use (&$analysisLinks, &$seenIds) {
                                          if (empty($attributes)) return;
                                          foreach ($attributes as $attr) {
                                              if (isset($seenIds[$attr['id']])) continue;
                                              if (isset($attr['category']) && $attr['category'] === 'External analysis') {
                                                  if ($attr['type'] === 'link' || $attr['type'] === 'url') {
                                                      $analysisLinks[] = ['value' => $attr['value'], 'type' => 'link', 'id' => $attr['id']];
                                                      $seenIds[$attr['id']] = true;
                                                  } elseif ($attr['type'] === 'attachment' && stripos($attr['value'], '.pdf') !== false) {
                                                      $analysisLinks[] = ['value' => $attr['value'], 'type' => 'attachment', 'id' => $attr['id']];
                                                      $seenIds[$attr['id']] = true;
                                                  }
                                              }
                                          }
                                      };

                                      if (!empty($event['Attribute'])) {
                                          $extractFromAttributes($event['Attribute']);
                                      }
                                      if (!empty($event['Object'])) {
                                          foreach ($event['Object'] as $obj) {
                                              if (!empty($obj['Attribute'])) {
                                                  $extractFromAttributes($obj['Attribute']);
                                              }
                                          }
                                      }
                                      if (!empty($event['objects'])) {
                                          $betaAttrs = [];
                                          foreach ($event['objects'] as $item) {
                                              if (isset($item['objectType']) && $item['objectType'] === 'attribute') {
                                                  $betaAttrs[] = $item;
                                              } elseif (isset($item['objectType']) && $item['objectType'] === 'object' && !empty($item['Attribute'])) {
                                                  $betaAttrs = array_merge($betaAttrs, $item['Attribute']);
                                              }
                                          }
                                          if (!empty($betaAttrs)) {
                                              $extractFromAttributes($betaAttrs);
                                          }
                                      }

                                      usort($analysisLinks, function($a, $b) {
                                          return strcasecmp($a['value'], $b['value']);
                                      });
                                      $analysisLinkCount = count($analysisLinks);
                                      $analysisInitialVisible = 3;
                                      $analysisHiddenCount = max($analysisLinkCount - $analysisInitialVisible, 0);
                                  ?>
                                  <div class="analysis-links-section" style="margin-top: 20px; border-top: 1px solid #eee; padding-top: 15px;">
                                      <h5 style="margin-top: 0; font-size: 13px; color: #666;">
                                          <?php echo __('Analysis links'); ?> <span class="beta-header-count"><?php echo '(' . h($analysisLinkCount) . ')'; ?></span>
                                          <span style="font-weight: normal; margin-left: 6px;"><i class="fa fa-exclamation-triangle"></i> <?php echo __('Open links cautiously'); ?></span>
                                      </h5>
                                      <?php if (!empty($analysisLinks)): ?>
                                          <ul id="analysis-links-list" style="list-style: none; padding: 0; margin: 0;">
                                              <?php foreach ($analysisLinks as $index => $link): ?>
                                                  <?php $isHidden = $index >= $analysisInitialVisible; ?>
                                                  <li class="analysis-link-item<?php echo $isHidden ? ' analysis-link-item-extra' : ''; ?>" style="margin-bottom: 8px; border-bottom: 1px solid #f0f0f0; padding-bottom: 5px; word-break: break-all;<?php echo $isHidden ? ' display: none;' : ''; ?>">
                                                      <?php if ($link['type'] === 'link'): ?>
                                                          <i class="fa fa-external-link-alt" style="color: #428bca; margin-right: 5px;"></i>
                                                          <a href="<?php echo h($link['value']); ?>" target="_blank" rel="noreferrer noopener"><?php echo h($link['value']); ?></a>
                                                      <?php else: ?>
                                                          <i class="fa fa-file-pdf" style="color: #d9534f; margin-right: 5px;"></i>
                                                          <a href="<?php echo $baseurl; ?>/attributes/download/<?php echo h($link['id']); ?>"><?php echo h($link['value']); ?></a> (<?php echo __('PDF Attachment'); ?>)
                                                      <?php endif; ?>
                                                  </li>
                                              <?php endforeach; ?>
                                          </ul>
                                          <?php if ($analysisHiddenCount > 0): ?>
                                              <a href="#" id="analysis-links-toggle" data-expanded="0" data-show-more-label="<?php echo h(__('Show all')); ?>" data-show-less-label="<?php echo h(__('Show less')); ?>" data-hidden-count="<?php echo h($analysisHiddenCount); ?>" onclick="toggleAnalysisLinks(); return false;" style="display: inline-block; margin-top: 8px;">
                                                  <?php echo __('Show all'); ?> (<?php echo h($analysisHiddenCount); ?> <?php echo __('more'); ?>)
                                              </a>
                                          <?php endif; ?>
                                      <?php endif; ?>
                                  </div>
                              </div>
                          </div>
                         
                          <!-- Analysis comments -->
                          <div class="beta-card summary-card beta-card-accent beta-card-accent-comments">
                              <div class="beta-card-header"><?php echo __('Analysis comments'); ?></div>
                              <div class="beta-card-body">
                                   <div id="comments-graph" style="width: 100%;"></div>
                              </div>
                         </div>

                      </div>
                      <div class="span4">
                           <div class="beta-card summary-card beta-card-accent beta-card-accent-reports" id="summary-reports-section">
                              <div class="beta-card-header beta-expandable-header" onclick="toggleSummaryReports();" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleSummaryReports();}" role="button" tabindex="0" aria-label="<?php echo __('Toggle event reports'); ?>">
                                  <?php echo __('Event reports'); ?> <span class="beta-header-count">(<span id="beta-event-reports-count"><?php echo h($eventReportCount); ?></span>)</span>
                                  <i id="summary-reports-toggle-icon" class="fa fa-chevron-right pull-right"></i>
                              </div>
                              <div class="beta-card-body" id="summary-reports-content-wrap" style="display:none;">
                                  <div id="summary-reports-content">
                                      <div class="text-center" style="padding: 12px 0;">
                                          <i class="fa fa-spinner fa-spin"></i>
                                      </div>
                                  </div>
                              </div>
                          </div>

                          <?php
                               $eventTagCount = !empty($event['EventTag']) ? count($event['EventTag']) : 0;
                               $canAddGlobalTag = $this->Acl->canModifyTag($event);
                               $canAddLocalTag = $this->Acl->canModifyTag($event, true);
                               $tagAccess = $canAddGlobalTag;
                               $localTagAccess = $canAddLocalTag;
                               $targetId = $event['Event']['id'];
                               $galaxyCount = 0;
                               if (!empty($event['Galaxy'])) {
                                   foreach ($event['Galaxy'] as $galaxyGroup) {
                                       if (!empty($galaxyGroup['GalaxyCluster'])) {
                                           $galaxyCount += count($galaxyGroup['GalaxyCluster']);
                                       }
                                   }
                               }
                          ?>
                          <div class="beta-context-section beta-context-section-collections">
                                       <div class="beta-context-section-header beta-collections-header-row">
                                           <span class="beta-collections-header-left beta-context-section-title">
                                               <strong><?php echo __('Collections'); ?> <span class="beta-header-count">(<span id="beta-collections-count">0</span>)</span></strong>
                                          </span>
                                          <span class="beta-context-section-actions">
                                              <?php if ($this->Acl->canAccess('collectionElements', 'addElementToCollection')): ?>
                                                  <a href="#"
                                                     onclick="openGenericModal('<?php echo $baseurl; ?>/collectionElements/addElementToCollection/Event/<?php echo h($event['Event']['uuid']); ?>'); return false;"
                                                     class="useCursorPointer addButton btn btn-inverse noPrint"
                                                     data-toggle="tooltip"
                                                     data-placement="top"
                                                     role="button"
                                                     tabindex="0"
                                                     aria-label="<?php echo __('Add to Collection'); ?>"
                                                     title="<?php echo __('Add to Collection'); ?>">
                                                      <i class="fa fa-folder-plus icon-white" style="color:#fff;"></i>
                                                  </a>
                                              <?php endif; ?>
                                          </span>
                                      </div>
                                       <div class="beta-context-section-body">
                                           <div id="event-collections-container">
                                               <span class="muted" style="font-size:11px;"><?php echo __('Loading…'); ?></span>
                                           </div>
                                       </div>
                          </div>

                          <div class="beta-context-section beta-context-section-tags">
                                       <div class="beta-context-section-header beta-collections-header-row">
                                           <span class="beta-collections-header-left beta-context-section-title">
                                               <strong><?php echo __('Tags'); ?> <span class="beta-header-count">(<span id="beta-tags-count"><?php echo h($eventTagCount); ?></span>)</span></strong>
                                          </span>
                                          <span class="beta-context-section-actions">
                                              <?php if ($canAddGlobalTag): ?>
                                                  <button title="<?php echo __('Add a tag'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Add a tag'); ?>" class="addTagButton addButton btn btn-inverse noPrint" data-toggle="tooltip" data-placement="top" data-popover-popup="<?php echo h($baseurl . '/tags/selectTaxonomy/' . $event['Event']['id']); ?>" data-popover-placement="left">
                                                      <i class="fas fa-globe-americas icon-white" style="color:#fff;"></i> <i class="fas fa-plus icon-white" style="color:#fff;"></i>
                                                  </button>
                                              <?php endif; ?>
                                               <?php if ($canAddLocalTag): ?>
                                                   <button title="<?php echo __('Add a local tag'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Add a local tag'); ?>" class="addLocalTagButton addButton btn btn-inverse noPrint" data-toggle="tooltip" data-placement="top" data-popover-popup="<?php echo h($baseurl . '/tags/selectTaxonomy/local:1/' . $event['Event']['id']); ?>" data-popover-placement="left">
                                                       <i class="fas fa-user icon-white" style="color:#fff;"></i> <i class="fas fa-plus icon-white" style="color:#fff;"></i>
                                                   </button>
                                              <?php endif; ?>
                                          </span>
                                      </div>
                                      <div class="beta-context-section-body">
                                          <span class="eventTagContainer">
                                              <?php
                                                    echo $this->element('ajaxTags', [
                                                        'event' => $event,
                                                        'tags' => $event['EventTag'],
                                                        'tagAccess' => $tagAccess,
                                                        'localTagAccess' => $localTagAccess,
                                                        'missingTaxonomies' => $missingTaxonomies,
                                                        'tagConflicts' => $tagConflicts,
                                                        'popoverPlacement' => 'left',
                                                        'hide_add_buttons' => true
                                                     ]);
                                               ?>
                                           </span>
                                       </div>
                          </div>

                          <div class="beta-context-section beta-context-section-galaxies">
                                       <div class="beta-context-section-header beta-collections-header-row">
                                           <span class="beta-collections-header-left beta-context-section-title">
                                               <strong><?php echo __('Galaxies'); ?> <span class="beta-header-count">(<span id="beta-galaxies-count"><?php echo h($galaxyCount); ?></span>)</span></strong>
                                          </span>
                                          <span class="beta-context-section-actions">
                                              <button type="button" class="btn btn-link btn-xs noPrint" id="beta-galaxies-expand-all-toggle" style="display:none; padding: 0 8px 0 0; vertical-align: middle;">
                                                  <?php echo __('Expand all'); ?>
                                              </button>
                                              <?php
                                                  if ($tagAccess) {
                                                      $link = "$baseurl/galaxies/selectGalaxyNamespace/$targetId/event/local:0";
                                                       echo sprintf(
                                                           '<button class="%s" data-popover-popup="%s" data-popover-placement="left" data-toggle="tooltip" data-placement="top" role="button" tabindex="0" aria-label="' . __('Add new cluster') . '" title="' . __('Add new cluster') . '">%s</button>',
                                                           'useCursorPointer addButton btn btn-inverse noPrint',
                                                           $link,
                                                           '<i class="fas fa-globe-americas"></i> <i class="fas fa-plus"></i>'
                                                       );
                                                  }
                                                  if ($localTagAccess) {
                                                      $link = "$baseurl/galaxies/selectGalaxyNamespace/$targetId/event/local:1";
                                                       echo sprintf(
                                                           '<button class="%s" data-popover-popup="%s" data-popover-placement="left" data-toggle="tooltip" data-placement="top" role="button" tabindex="0" aria-label="' . __('Add new local cluster') . '" title="' . __('Add new local cluster') . '">%s</button>',
                                                           'useCursorPointer addButton btn btn-inverse noPrint',
                                                           $link,
                                                           '<i class="fas fa-user"></i> <i class="fas fa-plus"></i>'
                                                       );
                                                  }
                                              ?>
                                          </span>
                                      </div>
                                      <div class="beta-context-section-body">
                                          <div class="beta-galaxies-container" id="galaxies_div" style="margin-top: 5px;">
                                            <?php
                                                if (!empty($event['Galaxy'])) {
                                                    foreach ($event['Galaxy'] as $galaxy) {
                                                        echo $this->element('Events/View/galaxy_compact_beta', [
                                                            'galaxyName' => $galaxy['name'],
                                                            'clusters' => $galaxy['GalaxyCluster'],
                                                            'baseurl' => $baseurl,
                                                            'canModify' => $tagAccess,
                                                            'canModifyLocal' => $localTagAccess,
                                                            'target_type' => 'event',
                                                            'target_id' => $targetId,
                                                        ]);
                                                    }
                                                }
                                            ?>
                                          </div>
                                       </div>
                          </div>
                           <!-- Warninglist Matches -->
                          <?php
                              $warninglistMatches = [];
                              $extractWarnings = function($attributes) use (&$warninglistMatches) {
                                  if (empty($attributes)) return;
                                  foreach ($attributes as $attr) {
                                      if (!empty($attr['warnings'])) {
                                          foreach ($attr['warnings'] as $w) {
                                              $key = $w['warninglist_name'] . '||' . $attr['value'];
                                              if (!isset($warninglistMatches[$key])) {
                                                  $warninglistMatches[$key] = [
                                                      'warninglist_name' => $w['warninglist_name'],
                                                      'value' => $attr['value'],
                                                      'count' => 0
                                                  ];
                                              }
                                              $warninglistMatches[$key]['count']++;
                                          }
                                      }
                                  }
                              };

                              if (!empty($event['Attribute'])) {
                                  $extractWarnings($event['Attribute']);
                              }
                              if (!empty($event['Object'])) {
                                  foreach ($event['Object'] as $obj) {
                                      if (!empty($obj['Attribute'])) {
                                          $extractWarnings($obj['Attribute']);
                                      }
                                  }
                              }
                              if (!empty($event['objects'])) {
                                  $betaAttrs = [];
                                  foreach ($event['objects'] as $item) {
                                      if (isset($item['objectType']) && $item['objectType'] === 'attribute') {
                                          $betaAttrs[] = $item;
                                      } elseif (isset($item['objectType']) && $item['objectType'] === 'object' && !empty($item['Attribute'])) {
                                          $betaAttrs = array_merge($betaAttrs, $item['Attribute']);
                                      }
                                  }
                                  if (!empty($betaAttrs)) {
                                      $extractWarnings($betaAttrs);
                                  }
                              }
                              usort($warninglistMatches, function($a, $b) {
                                  return strcasecmp($a['warninglist_name'], $b['warninglist_name']) ?: strcasecmp($a['value'], $b['value']);
                              });
                              $warninglistMatchCount = count($warninglistMatches);
                              $warninglistExpanded = $warninglistMatchCount > 0;
                          ?>
                          <div class="beta-card summary-card">
                                <div class="beta-card-header beta-expandable-header" onclick="toggleWarninglistSection();" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleWarninglistSection();}" role="button" tabindex="0" aria-label="<?php echo __('Toggle warninglist matches'); ?>">
                                    <?php echo __('Warninglist Matches'); ?> <span class="beta-header-count">(<?php echo h($warninglistMatchCount); ?>)</span>
                                    <i id="beta-warninglist-toggle-icon" class="fa <?php echo $warninglistExpanded ? 'fa-chevron-down' : 'fa-chevron-right'; ?> pull-right"></i>
                                </div>
                                <div class="beta-card-body" id="beta-warninglist-content-wrap" style="display: <?php echo $warninglistExpanded ? 'block' : 'none'; ?>;">
                                    <?php if (!empty($warninglistMatches)): ?>
                                        <table class="table table-condensed table-hover beta-warninglist-table" style="font-size: 12px; margin-bottom: 0;">
                                            <thead>
                                               <tr>
                                                   <th><?php echo __('Warninglist'); ?></th>
                                                   <th><?php echo __('Value'); ?></th>
                                               </tr>
                                           </thead>
                                           <tbody>
                                               <?php foreach ($warninglistMatches as $match): ?>
                                                   <tr>
                                                       <td><span class="label label-warning"><?php echo h($match['warninglist_name']); ?></span></td>
                                                       <td>
                                                            <a href="#attributes" onclick="$('.nav-tabs a[href=\'#attributes\']').tab('show'); $('#beta-attr-search').val(<?php echo h(json_encode($match['value'])); ?>).trigger('keyup'); return false;" class="attr-value">
                                                               <?php echo h($match['value']); ?>
                                                           </a>
                                                       </td>
                                                   </tr>
                                               <?php endforeach; ?>
                                           </tbody>
                                       </table>
                                   <?php else: ?>
                                       <p class="muted" style="font-size: 12px;"><?php echo __('No warninglist matches found.'); ?></p>
                                   <?php endif; ?>
                               </div>
                           </div>

                           <!-- Export Card -->
                           <?php
                               $eventId = $event['Event']['id'];
                               $isPublished = !empty($event['Event']['published']);
                               $betaExportFormats = [
                                   'json' => [
                                       'label' => __('MISP JSON'),
                                       'url' => $baseurl . '/events/restSearch/json/includeAnalystData:1/eventid:' . $eventId . '.json',
                                       'checkbox' => true,
                                       'checkbox_label' => __('Encode Attachments'),
                                       'checkbox_url' => $baseurl . '/events/restSearch/json/withAttachments:1/includeAnalystData:1/eventid:' . $eventId . '.json',
                                       'icon' => 'fa-file-code',
                                   ],
                                   'xml' => [
                                       'label' => __('MISP XML'),
                                       'url' => $baseurl . '/events/restSearch/xml/eventid:' . $eventId . '.xml',
                                       'checkbox' => true,
                                       'checkbox_label' => __('Encode Attachments'),
                                       'checkbox_url' => $baseurl . '/events/restSearch/xml/eventid:' . $eventId . '/withAttachments:1.xml',
                                       'icon' => 'fa-file-code',
                                   ],
                                   'csv' => [
                                       'label' => $isPublished ? __('CSV') : __('CSV (IDS flag ignored)'),
                                       'url' => $isPublished
                                           ? $baseurl . '/events/restSearch/returnFormat:csv/to_ids:1/published:1/includeContext:0/eventid:' . $eventId
                                           : $baseurl . '/events/restSearch/returnFormat:csv/includeContext:0/eventid:' . $eventId,
                                       'checkbox' => $isPublished,
                                       'checkbox_label' => __('Include non-IDS marked attributes'),
                                       'checkbox_url' => $baseurl . '/events/restSearch/returnFormat:csv/to_ids:1||0/published:1||0/includeContext:0/eventid:' . $eventId,
                                       'icon' => 'fa-file-csv',
                                   ],
                                   'csv_context' => [
                                       'label' => __('CSV with context'),
                                       'url' => $isPublished
                                           ? $baseurl . '/events/restSearch/returnFormat:csv/to_ids:1/published:1/includeContext:1/eventid:' . $eventId
                                           : $baseurl . '/events/restSearch/returnFormat:csv/includeContext:1/eventid:' . $eventId,
                                       'checkbox' => $isPublished,
                                       'checkbox_label' => __('Include non-IDS marked attributes'),
                                       'checkbox_url' => $baseurl . '/events/restSearch/returnFormat:csv/to_ids:1||0/published:1||0/includeContext:1/eventid:' . $eventId,
                                       'icon' => 'fa-file-csv',
                                   ],
                                   'stix_xml' => [
                                       'label' => __('STIX 1 XML'),
                                       'url' => $baseurl . '/events/restSearch/stix/eventid:' . $eventId,
                                       'checkbox' => true,
                                       'checkbox_label' => __('Encode Attachments'),
                                       'checkbox_url' => $baseurl . '/events/restSearch/stix/eventid:' . $eventId . '/withAttachments:1',
                                       'icon' => 'fa-file-alt',
                                   ],
                                   'stix_json' => [
                                       'label' => __('STIX 1 JSON'),
                                       'url' => $baseurl . '/events/restSearch/stix-json/eventid:' . $eventId,
                                       'checkbox' => true,
                                       'checkbox_label' => __('Encode Attachments'),
                                       'checkbox_url' => $baseurl . '/events/restSearch/stix-json/withAttachments:1/eventid:' . $eventId,
                                       'icon' => 'fa-file-alt',
                                   ],
                                   'stix2' => [
                                       'label' => __('STIX 2'),
                                       'url' => $baseurl . '/events/restSearch/stix2/eventid:' . $eventId,
                                       'checkbox' => true,
                                       'checkbox_label' => __('Encode Attachments'),
                                       'checkbox_url' => $baseurl . '/events/restSearch/stix2/eventid:' . $eventId . '/withAttachments:1',
                                       'icon' => 'fa-file-alt',
                                   ],
                                   'openioc' => [
                                       'label' => __('OpenIOC'),
                                       'url' => $baseurl . '/events/restSearch/openioc/to_ids:1/published:1/eventid:' . $eventId . '.json',
                                       'checkbox' => false,
                                       'icon' => 'fa-file-alt',
                                   ],
                                   'rpz' => [
                                       'label' => __('RPZ Zone file'),
                                       'url' => $baseurl . '/attributes/restSearch/returnFormat:rpz/published:1||0/eventid:' . $eventId,
                                       'checkbox' => false,
                                       'icon' => 'fa-file-alt',
                                   ],
                                   'suricata' => [
                                       'label' => __('Suricata rules'),
                                       'url' => $baseurl . '/events/restSearch/returnFormat:suricata/published:1||0/eventid:' . $eventId,
                                       'checkbox' => false,
                                       'icon' => 'fa-shield-alt',
                                   ],
                                   'snort' => [
                                       'label' => __('Snort rules'),
                                       'url' => $baseurl . '/events/restSearch/returnFormat:snort/published:1||0/eventid:' . $eventId,
                                       'checkbox' => false,
                                       'icon' => 'fa-shield-alt',
                                   ],
                                   'text' => [
                                       'label' => __('Text (attribute values)'),
                                       'url' => $baseurl . '/attributes/restSearch/returnFormat:text/published:1||0/eventid:' . $eventId,
                                       'checkbox' => true,
                                       'checkbox_label' => __('Include non-IDS marked attributes'),
                                       'checkbox_url' => $baseurl . '/attributes/restSearch/returnFormat:text/published:1||0/to_ids:1||0/eventid:' . $eventId,
                                       'icon' => 'fa-file-alt',
                                   ],
                               ];
                           ?>
                            <div class="beta-card summary-card" id="beta-export-card">
                                <div class="beta-card-header beta-expandable-header" onclick="toggleExportSection();" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleExportSection();}" role="button" tabindex="0" aria-label="<?php echo __('Toggle export options'); ?>">
                                    <i class="fa fa-download" style="margin-right: 6px;"></i><?php echo __('Export'); ?>
                                    <i id="beta-export-toggle-icon" class="fa fa-chevron-right pull-right"></i>
                                </div>
                                <div class="beta-card-body" id="beta-export-content-wrap" style="display:none;">
                                    <div style="margin-bottom: 10px;">
                                        <label for="beta-export-format" style="font-size: 12px; font-weight: 600; color: #666; display: block; margin-bottom: 4px;"><?php echo __('Format'); ?></label>
                                        <select id="beta-export-format" class="form-control input-sm" onchange="exportFormatChanged(this.value)" style="width: 100%;">
                                           <?php foreach ($betaExportFormats as $fmtKey => $fmt): ?>
                                               <option value="<?php echo h($fmtKey); ?>"
                                                   data-url="<?php echo h($fmt['url']); ?>"
                                                   data-checkbox="<?php echo $fmt['checkbox'] ? '1' : '0'; ?>"
                                                   data-checkbox-label="<?php echo isset($fmt['checkbox_label']) ? h($fmt['checkbox_label']) : ''; ?>"
                                                   data-checkbox-url="<?php echo isset($fmt['checkbox_url']) ? h($fmt['checkbox_url']) : ''; ?>"
                                               ><?php echo h($fmt['label']); ?></option>
                                           <?php endforeach; ?>
                                       </select>
                                   </div>
                                   <div id="beta-export-checkbox-row" style="margin-bottom: 10px; display: none;">
                                       <label style="font-size: 12px; font-weight: normal; color: #555; cursor: pointer;">
                                           <input type="checkbox" id="beta-export-checkbox" style="margin-right: 5px; vertical-align: middle;">
                                           <span id="beta-export-checkbox-label"></span>
                                       </label>
                                   </div>
                                   <a id="beta-export-download-btn"
                                      href="#"
                                      class="btn btn-primary btn-sm"
                                      style="display: block; text-align: center;"
                                      onclick="exportDownload(); return false;">
                                       <i class="fa fa-download"></i> <?php echo __('Download'); ?>
                                   </a>
                               </div>
                           </div>
                       </div>
                  </div>
                 </div>

            <!-- Attributes Tab -->
            <div role="tabpanel" class="tab-pane" id="attributes">
                 <div class="beta-attributes-top-panel">
                     <div class="beta-composition-row">
                         <div class="beta-composition-label"><?php echo __('Composition'); ?></div>
                         <div id="composition-treemap" class="composition-singlebar-wrap"></div>
                     </div>
                     <div id="beta-filter-banner-slot"></div>
                     <div id="beta-attributes-container">
                      <?php if ($hasBulkAttributePermissions): ?>
                      <div id="beta-bulk-actions-bar" class="beta-bulk-actions-bar">
                           <div class="beta-bulk-actions-bar-inner">
                               <div class="beta-bulk-actions-summary">
                                   <span id="beta-bulk-selected-count">0</span> <?php echo __('selected'); ?>
                               </div>
                                <div class="beta-bulk-actions-buttons">
                                     <div class="beta-bulk-actions-group">
                                    <?php if ($bulkAttributePermissions['edit']): ?>
                                     <button type="button" class="btn btn-default btn-sm" onclick="editSelectedAttributes(<?php echo h($event['Event']['id']); ?>); return false;" title="<?php echo __('Edit selected attributes'); ?>" aria-label="<?php echo __('Edit selected attributes'); ?>">
                                         <i class="fa fa-edit"></i> <?php echo __('Bulk Edit'); ?>
                                     </button>
                                    <?php endif; ?>
                                    <?php if ($bulkAttributePermissions['tagGlobal'] || $bulkAttributePermissions['tagLocal']): ?>
                                     <div class="beta-bulk-menu-wrap" data-beta-bulk-menu>
                                         <button type="button" class="btn btn-default btn-sm beta-bulk-menu-trigger" data-beta-bulk-menu-trigger aria-expanded="false" aria-haspopup="true" title="<?php echo __('Add a tag to selected attributes'); ?>">
                                             <i class="fa fa-tag"></i> <?php echo __('Tag'); ?> <i class="fa fa-caret-up"></i>
                                         </button>
                                         <div class="beta-bulk-menu" data-beta-bulk-menu-panel>
                                            <?php if ($bulkAttributePermissions['tagGlobal']): ?>
                                             <button type="button" onclick="openBetaBulkTagPicker(false); return false;">
                                                 <i class="fa fa-globe"></i> <?php echo __('Global'); ?>
                                             </button>
                                            <?php endif; ?>
                                            <?php if ($bulkAttributePermissions['tagLocal']): ?>
                                             <button type="button" onclick="openBetaBulkTagPicker(true); return false;">
                                                 <i class="fa fa-user"></i> <?php echo __('Local'); ?>
                                             </button>
                                            <?php endif; ?>
                                         </div>
                                     </div>
                                    <?php endif; ?>
                                    <?php if ($bulkAttributePermissions['galaxyGlobal'] || $bulkAttributePermissions['galaxyLocal']): ?>
                                     <div class="beta-bulk-menu-wrap" data-beta-bulk-menu>
                                         <button type="button" class="btn btn-default btn-sm beta-bulk-menu-trigger" data-beta-bulk-menu-trigger aria-expanded="false" aria-haspopup="true" title="<?php echo __('Add a galaxy cluster to selected attributes'); ?>">
                                             <i class="fa fa-bahai"></i> <?php echo __('Galaxies'); ?> <i class="fa fa-caret-up"></i>
                                         </button>
                                         <div class="beta-bulk-menu" data-beta-bulk-menu-panel>
                                            <?php if ($bulkAttributePermissions['galaxyGlobal']): ?>
                                             <button type="button" onclick="openBetaBulkGalaxyPicker(false); return false;">
                                                 <i class="fa fa-globe"></i> <?php echo __('Global'); ?>
                                             </button>
                                            <?php endif; ?>
                                            <?php if ($bulkAttributePermissions['galaxyLocal']): ?>
                                             <button type="button" onclick="openBetaBulkGalaxyPicker(true); return false;">
                                                 <i class="fa fa-user"></i> <?php echo __('Local'); ?>
                                             </button>
                                            <?php endif; ?>
                                         </div>
                                     </div>
                                    <?php endif; ?>
                                    <?php if ($bulkAttributePermissions['groupIntoObject']): ?>
                                     <button type="button" class="btn btn-default btn-sm" onclick="openBetaGroupIntoObject(<?php echo h($event['Event']['id']); ?>, this); return false;" title="<?php echo __('Group selected attributes into an object'); ?>" aria-label="<?php echo __('Group selected attributes into an object'); ?>">
                                         <i class="fa fa-object-group"></i> <?php echo __('Group Into Object'); ?>
                                     </button>
                                    <?php endif; ?>
                                    <?php if ($bulkAttributePermissions['addRelationships']): ?>
                                    <button type="button" class="btn btn-default btn-sm" onclick="openBetaBulkRelationships(<?php echo h($event['Event']['id']); ?>); return false;" title="<?php echo __('Create a new relationship for selected entities'); ?>" aria-label="<?php echo __('Create a new relationship for selected entities'); ?>">
                                        <i class="fas fa-project-diagram"></i> <?php echo __('New Relationship'); ?>
                                    </button>
                                    <?php endif; ?>
                                    <?php if ($bulkAttributePermissions['sightings']): ?>
                                     <button type="button" class="btn btn-default btn-sm sightings_advanced_add" data-object-id="selected" data-object-context="attribute" title="<?php echo __('Show sightings for selected attributes'); ?>" aria-label="<?php echo __('Show sightings for selected attributes'); ?>">
                                         <i class="fa fa-wrench"></i> <?php echo __('Sightings'); ?>
                                     </button>
                                    <?php endif; ?>
                                     </div>
                                    <?php if ($bulkAttributePermissions['delete']): ?>
                                     <div class="beta-bulk-actions-group beta-bulk-actions-group-danger">
                                         <button type="button" class="btn btn-danger btn-sm" onclick="handleBetaBulkDeleteAction(<?php echo h($event['Event']['id']); ?>); return false;">
                                             <i class="fa fa-trash"></i> <?php echo __('Delete'); ?>
                                         </button>
                                     </div>
                                    <?php endif; ?>
                                </div>
                           </div>
                       </div>
                     <?php endif; ?>
                      <div id="beta-attributes-list">
                          <?php echo $this->element('eventattribute', [
                               'items' => $items,
                              'betaTotalAttributes' => $betaTotalAttributes,
                             'paging' => $paging,
                             'betaCurrentPage' => $betaCurrentPage,
                             'betaPageSize' => $betaPageSize,
                             'betaTotalItems' => $betaTotalItems,
                             'betaTotalPages' => $betaTotalPages,
                             'betaShowStart' => $betaShowStart,
                             'betaShowEnd' => $betaShowEnd,
                              'hasBulkAttributePermissions' => $hasBulkAttributePermissions,
                              'bulkAttributePermissions' => $bulkAttributePermissions
                            ]); ?>
                      </div>
                     </div>
                 </div>
             </div>
            
             <!-- Other Tabs Placeholders -->
              <div role="tabpanel" class="tab-pane beta-tab-pane-tight" id="correlations">
                <div id="correlations-loader" style="text-align: center; padding: 40px;">
                    <i class="fa fa-spinner fa-spin fa-3x" style="color: #428bca; margin-bottom: 15px;"></i>
                    <p style="color: #666; font-size: 1.1em;"><?php echo __('Analyzing correlations...'); ?></p>
                </div>
                <div id="correlations-content" style="display: none;">
                    <div id="correlations-sankey-stage" class="beta-sankey-stage">
                        <div id="correlations-sankey-toolbar" style="display: flex; justify-content: flex-start; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 6px; min-height: 24px; width: 100%;">
                            <span id="sankey-filter-badge" style="display: none; background: #d9534f; color: #fff; font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 12px; white-space: nowrap;">
                                <i class="fa fa-filter"></i> <span id="sankey-filter-label"></span>
                                <a href="#" onclick="resetCorrelationFilter(); return false;" style="color: #fff; margin-left: 6px; text-decoration: none;" title="<?php echo __('Remove filter'); ?>"><i class="fa fa-times-circle"></i></a>
                            </span>
                            <span id="sankey-limit-msg" style="font-size: 12px; color: #7d8894;"></span>
                             <div class="beta-sankey-toggle-group">
                                 <label for="sankey-date-align-toggle" class="beta-sankey-toggle">
                                      <span class="beta-sankey-toggle-label"><?php echo __('Use timeline'); ?></span>
                                     <input type="checkbox" id="sankey-date-align-toggle" checked>
                                     <span class="beta-sankey-toggle-switch" aria-hidden="true"></span>
                                 </label>
                                 <label for="sankey-latest-events-toggle" class="beta-sankey-toggle">
                                      <span class="beta-sankey-toggle-label"><?php echo __('20 event limit'); ?></span>
                                     <input type="checkbox" id="sankey-latest-events-toggle">
                                     <span class="beta-sankey-toggle-switch" aria-hidden="true"></span>
                                 </label>
                                 <label for="sankey-show-publisher-toggle" class="beta-sankey-toggle">
                                     <span class="beta-sankey-toggle-label"><?php echo __('Show publisher'); ?></span>
                                     <input type="checkbox" id="sankey-show-publisher-toggle" checked>
                                     <span class="beta-sankey-toggle-switch" aria-hidden="true"></span>
                                 </label>
                             </div>
                         </div>
                        <div style="display: flex; align-items: flex-start; justify-content: center; width: 100%;">
                            <div id="correlations-sankey-shell" class="beta-sankey-shell" style="flex: 1 1 auto; max-width: 100%; margin: 0 auto;">
                                <div id="correlations-sankey" style="width: 100%; height: 400px; margin: 0 auto;"></div>
                            </div>
                        </div>
                    </div>
                    <div class="beta-event-timeline" id="correlationsEventTimeline" style="display:none;">
                        <div class="beta-event-timeline-header">
                            <span class="beta-event-timeline-title"><i class="fa fa-stream"></i> <?php echo __('Correlated event timeline'); ?></span>
                            <span class="beta-event-timeline-range" id="correlationsEventTimelineRange"></span>
                        </div>
                        <div class="beta-event-timeline-track">
                            <div class="beta-event-timeline-ticks" aria-hidden="true"></div>
                            <div class="beta-event-timeline-markers"></div>
                        </div>
                    </div>
                    <div id="correlations-filter-comments" class="beta-correlation-filter-comments"></div>
                    <div id="correlations-table-filter-banner" style="display: none; margin-bottom: 15px; padding: 10px 15px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; align-items: center; justify-content: space-between;">
                        <span><i class="fa fa-filter" style="color: #856404;"></i> <strong><?php echo __('Filtered view'); ?></strong> &mdash; <span id="correlations-table-filter-msg"></span></span>
                        <a href="#" onclick="resetCorrelationFilter(); return false;" class="btn btn-xs btn-warning" style="margin-left: 10px;"><i class="fa fa-times"></i> <?php echo __('Clear Filter'); ?></a>
                    </div>
                    <div id="correlations-table-container"></div>
                </div>
            </div>
             <div role="tabpanel" class="tab-pane" id="history">
                <div style="margin-bottom: 20px;">
                    <h3 style="margin: 0;"><?php echo __('History'); ?></h3>
                </div>
                
                <?php if (!empty($contributors)): ?>
                    <p style="margin-bottom: 20px;"><strong><?php echo __('Contributors'); ?>:</strong> <?php echo h(implode(', ', $contributors)); ?></p>
                <?php endif; ?>
                
                <div id="history-content-container">
                    <div class="text-center" style="padding: 40px;">
                        <i class="fa fa-spinner fa-spin fa-2x"></i><br>
                        <?php echo __('Loading history...'); ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    // Improved Treemap Logic
    <?php
        $compositionData = [];
        $attrTypes = [];
        $seenAttrKeys = [];
        $commentCounts = [];

        $registerAttrType = function($attr) use (&$attrTypes, &$seenAttrKeys) {
            if (empty($attr) || empty($attr['type'])) {
                return;
            }

            $key = null;
            if (!empty($attr['id'])) {
                $key = 'id:' . $attr['id'];
            } elseif (!empty($attr['uuid'])) {
                $key = 'uuid:' . $attr['uuid'];
            }

            if ($key !== null) {
                if (isset($seenAttrKeys[$key])) {
                    return;
                }
                $seenAttrKeys[$key] = true;
            }

            $t = $attr['type'];
            if (!isset($attrTypes[$t])) {
                $attrTypes[$t] = 0;
            }
            $attrTypes[$t]++;
        };

        $registerComment = function($value) use (&$commentCounts) {
            if (empty($value)) {
                return;
            }
            if (!isset($commentCounts[$value])) {
                $commentCounts[$value] = 0;
            }
            $commentCounts[$value]++;
        };

        $processAttribute = function($attr) use ($registerAttrType, $registerComment) {
            $registerAttrType($attr);
            $registerComment($attr['comment'] ?? null);
        };

        $processObject = function($obj) use ($processAttribute, $registerComment) {
            $registerComment($obj['comment'] ?? null);
            if (empty($obj['Attribute'])) {
                return;
            }
            foreach ($obj['Attribute'] as $attr) {
                $processAttribute($attr);
            }
        };

        if (!empty($event['objects'])) {
            foreach ($event['objects'] as $obj) {
                if ($obj['objectType'] === 'attribute') {
                    $processAttribute($obj);
                } elseif ($obj['objectType'] === 'object') {
                    $processObject($obj);
                }
            }
        }

        if (!empty($event['Attribute'])) {
             foreach ($event['Attribute'] as $attr) {
                $processAttribute($attr);
            }
        }

        if (!empty($event['Object'])) {
             foreach ($event['Object'] as $obj) {
                $processObject($obj);
            }
        }
        
        foreach ($attrTypes as $type => $count) {
            $compositionData[] = [
                'label' => "Attribute: $type",
                'name' => $type,
                'value' => $count,
                'type' => 'attribute'
            ];
        }
        
        // Sort by value desc
        usort($compositionData, function($a, $b) {
            return $b['value'] - $a['value'];
        });

        $commentData = [];
        foreach ($commentCounts as $comment => $count) {
            $commentData[] = [
                'label' => $comment,
                'value' => $count
            ];
        }
        usort($commentData, function($a, $b) {
            return $b['value'] - $a['value'];
        });
    ?>
    var compositionData = <?php echo json_encode($compositionData); ?>;
    var commentData = <?php echo json_encode($commentData); ?>;

    function escapeHtml(value) {
        return $('<div/>').text(value == null ? '' : String(value)).html();
    }

    function renderCompositionBar() {
        var compositionContainer = $('#composition-treemap');
        if (!compositionContainer.length) return;

        if (!compositionData || compositionData.length === 0) {
             d3.select("#composition-treemap").html('<div class="alert alert-info" style="margin: 20px;">No composition data available.</div>');
            return;
        }

        var width = compositionContainer.width() || 0;
        if (width < 10) return;

        compositionContainer.empty();
        compositionContainer.css('position', 'relative');

        var total = d3.sum(compositionData, function(d) { return d.value; });
        var color = d3.scale.ordinal()
            .range(["#3f6f9e", "#66a683", "#d3a259", "#c66b6b", "#5f98ad", "#8a7bb8", "#8aa05d", "#b58562"])
            .domain(compositionData.map(function(d) { return d.label; }));

        var barWrap = $('<div class="composition-singlebar"></div>');
        compositionContainer.append(barWrap);

        var xOffset = 0;
        var layout = [];

        compositionData.forEach(function(d) {
            var percent = total > 0 ? (d.value / total) * 100 : 0;
            var pixelWidth = (percent / 100) * width;
            var segmentColor = color(d.label);

            var segment = $('<div class="segment" title="' + escapeHtml(d.label) + ' (' + d.value + ', ' + percent.toFixed(2) + '%)"></div>');
            segment.css({
                width: percent + '%',
                background: segmentColor
            });
            segment.on('click', function() {
                filterAttributesByComposition(d.type, d.name);
            });
            barWrap.append(segment);

            layout.push({
                data: d,
                startX: xOffset,
                centerX: xOffset + (pixelWidth / 2),
                pixelWidth: pixelWidth,
                color: segmentColor
            });

            xOffset += pixelWidth;
        });

        var overlaySvg = d3.select('#composition-treemap')
            .append('svg')
            .attr('width', width)
            .attr('height', 30)
            .style('position', 'absolute')
            .style('top', '0')
            .style('left', '0')
            .style('pointer-events', 'none');

        layout.forEach(function(item) {
            if (item.pixelWidth >= 70) {
                overlaySvg.append('text')
                    .attr('class', 'composition-inline-label')
                    .attr('x', item.centerX)
                    .attr('y', 19)
                    .attr('text-anchor', 'middle')
                    .text(item.data.name + ' (' + item.data.value + ')');
            }
        });

        var labelGrid = $('<div class="composition-label-grid"></div>');
        compositionContainer.append(labelGrid);
        var smallItems = layout.filter(function(item) {
            return item.pixelWidth < 70;
        });

        if (smallItems.length > 0) {
            smallItems.sort(function(a, b) {
                if (b.data.value !== a.data.value) {
                    return b.data.value - a.data.value;
                }
                return a.data.name.localeCompare(b.data.name);
            });

            var labelList = $('<div class="composition-label-list"></div>');
            labelGrid.append(labelList);

            smallItems.forEach(function(item) {
                var chip = $('<div class="composition-label-chip" title="' + escapeHtml(item.data.label) + '"></div>');
                chip.append('<span class="swatch" style="background:' + item.color + ';"></span>');
                chip.append('<span><strong>' + escapeHtml(item.data.name) + '</strong> (' + item.data.value + ')</span>');
                chip.on('click', function() {
                    filterAttributesByComposition(item.data.type, item.data.name);
                });
                labelList.append(chip);
            });
        }
    }

    $(function() {
        popoverStartup();
        $(document)
            .off('click.betaBulkMenuTrigger')
            .on('click.betaBulkMenuTrigger', '[data-beta-bulk-menu-trigger]', function(e) {
                e.preventDefault();
                e.stopPropagation();
                toggleBetaBulkMenu(this);
            })
            .off('click.betaBulkMenuPanel')
            .on('click.betaBulkMenuPanel', '[data-beta-bulk-menu-panel] button', function() {
                closeBetaBulkMenus();
            })
            .off('click.betaBulkMenuOutside')
            .on('click.betaBulkMenuOutside', function(e) {
                if (!$(e.target).closest('[data-beta-bulk-menu]').length) {
                    closeBetaBulkMenus();
                }
            });

        var initialAttributeAnchor = null;
        var initialFocusUuid = null;
        var focusRetryCount = 0;
        var focusMatch = window.location.pathname.match(/\/focus:([^\/]+)/);
        if (focusMatch && focusMatch[1]) {
            initialFocusUuid = decodeURIComponent(focusMatch[1]);
        }

        function applyFocusUuid() {
            if (!initialFocusUuid || typeof focusObjectByUuid !== 'function') {
                return;
            }
            if (focusObjectByUuid(initialFocusUuid)) {
                initialFocusUuid = null;
                focusRetryCount = 0;
                return;
            }
            if (focusRetryCount < 10) {
                focusRetryCount++;
                setTimeout(applyFocusUuid, 150);
            }
        }

        function scrollToAttributeAnchor(attempt) {
            var hash = initialAttributeAnchor || window.location.hash || '';
            if (hash.indexOf('#Attribute_') !== 0) {
                return;
            }
            var targetId = hash.substring(1);
            var target = document.getElementById(targetId);
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'center' });
                $('.beta-deeplink-highlight').removeClass('beta-deeplink-highlight');
                $(target).addClass('beta-deeplink-highlight');
                initialAttributeAnchor = null;
            } else if ((attempt || 0) < 12) {
                setTimeout(function() {
                    scrollToAttributeAnchor((attempt || 0) + 1);
                }, 150);
            }
        }

        $('a[data-toggle="tab"][href="#attributes"]').on('shown.bs.tab', function () {
            renderCompositionBar();
            applyFocusUuid();
            scrollToAttributeAnchor();
        });

        $(window).on('resize', function() {
            if ($('#attributes').hasClass('active')) {
                renderCompositionBar();
            }
        });

        if ($('#attributes').hasClass('active')) {
            renderCompositionBar();
        }

        // Comments List
        if (commentData && commentData.length > 0) {
            var container = d3.select("#comments-graph");
            container.html(""); // Clear
            var list = container.append("ul")
                .attr("class", "comment-bullet-list");

            commentData.forEach(function(d) {
                var actionText = 'Show ' + d.value + ' matching attribute' + (d.value === 1 ? '' : 's') + ' for this comment';
                var row = list.append("li")
                    .attr("class", "comment-bullet-item");

                var action = row.append("button")
                    .attr("type", "button")
                    .attr("class", "comment-bullet-action")
                    .attr("title", actionText)
                    .attr("aria-label", actionText)
                    .on("click", function() {
                        filterAttributesByComment(d.label);
                    });

                action.append("span")
                    .attr("class", "comment-bullet-label")
                    .text(d.label);

                action.append("span")
                    .attr("class", "comment-bullet-count")
                    .text(d.value);

            });
        } else {
             d3.select("#comments-graph").html('<div class="alert alert-info" style="margin: 20px;">No comment data available.</div>');
        }

        // Initialize history state on load
        var historyTab = (history.state && history.state.tab) ? history.state.tab : '';
        var rawHash = window.location.hash || historyTab || '';
        var initialTab = '#summary';
        var initialUrlHash = '#summary';
        if (rawHash === '#summary' || rawHash === '#attributes' || rawHash === '#correlations' || rawHash === '#history') {
            initialTab = rawHash;
            initialUrlHash = rawHash;
        } else if (rawHash.indexOf('#Attribute_') === 0) {
            initialTab = '#attributes';
            initialUrlHash = rawHash;
            initialAttributeAnchor = rawHash;
        }

        window.ignoreTabPush = true;
        if (initialTab !== '#summary') {
            $('.nav-tabs a[href="' + initialTab + '"]').tab('show');
        }

        var initialState = {
            tab: initialTab,
            filter: null
        };
        history.replaceState(initialState, '', window.location.pathname + initialUrlHash);

        window.ignoreTabPush = false;

        $('.nav-tabs a').on('shown.bs.tab', function (e) {
            if (window.ignoreTabPush) return;
            var target = $(e.target).attr("href");
            var currentState = history.state;
            
            // Only push if it's different from the current tab in history
            if (!currentState || currentState.tab !== target) {
                history.pushState({ tab: target, filter: null }, '', window.location.pathname + target);
            }
        });

        window.onpopstate = function(event) {
            if (event.state && event.state.tab) {
                window.ignoreTabPush = true;
                $('.nav-tabs a[href="' + event.state.tab + '"]').tab('show');
                window.ignoreTabPush = false;
            }
        };

        window.summaryPrimaryReportId = <?php echo !empty($firstEventReportId) ? (int)$firstEventReportId : 0; ?>;

        function updateSummaryReportCount() {
            var count = $('#summary-reports-content .beta-report-row').length;
            $('#beta-event-reports-count').text(count);
        }

        // Load reports into summary tab
        $.get("<?php echo $baseurl; ?>/eventReports/index/event_id:<?php echo h($event['Event']['id']); ?>/index_for_event:1/beta:1", function(data) {
            $("#summary-reports-content").html(data);
            updateSummaryReportCount();
            if (window.eventTimestamps && typeof window.eventTimestamps.update === 'function') {
                window.eventTimestamps.update();
            }
        });

        // Load History when tab activated
        $('a[data-toggle="tab"][href="#history"]').on('shown.bs.tab', function (e) {
            loadHistory();
        });

        // Check if we are already on the history tab on page load
        if (window.location.hash === '#history') {
            loadHistory();
        }

        function loadHistory() {
            if ($('#history-content-container .beta-history-container').length > 0) return;
            var eventId = '<?php echo h($event['Event']['id']); ?>';
            $.get("<?php echo $baseurl; ?>/audit_logs/eventIndex/" + eventId + "/limit:20", function(data) {
                $("#history-content-container").html(data);
            }).fail(function() {
                $("#history-content-container").html('<div class="alert alert-danger"><?php echo __('Failed to load history.'); ?></div>');
            });
        }

        // Initialize export card
        var initialExportKey = $('#beta-export-format').val();
        if (initialExportKey) {
            exportFormatChanged(initialExportKey);
        }

        initContextCountObservers();
        refreshContextCounts();
        initBetaBulkActions();
        initBetaSingleDeleteRefresh();
        initBetaMassEditRefresh();
    });

    function buildFilterMessage(text) {
        var msg = '<div class="alert alert-warning filter-active-msg" style="margin-top: 10px;">';
        msg += '<button type="button" class="close" onclick="clearAttributeFilter(); $(this).parent().remove();">×</button>';
        msg += text;
        msg += ' <a href="#" onclick="clearAttributeFilter(); return false;">(Clear Filter)</a>';
        msg += '</div>';
        return msg;
    }

    function renderFilterMessage(message, preferredSelector) {
        var $target = $(preferredSelector);
        if ($target.length) {
            $target.html(message);
        } else {
            $('#attributes').prepend(message);
        }
    }

    function setSidebarSectionExpanded(contentSelector, iconSelector, expanded) {
        var $content = $(contentSelector);
        var $icon = $(iconSelector);
        if (!$content.length || !$icon.length) {
            return;
        }
        $content.toggle(!!expanded);
        $icon.toggleClass('fa-chevron-down', !!expanded).toggleClass('fa-chevron-right', !expanded);
    }

    function toggleSidebarSection(contentSelector, iconSelector) {
        var isExpanded = $(contentSelector).is(':visible');
        setSidebarSectionExpanded(contentSelector, iconSelector, !isExpanded);
    }

    function toggleWarninglistSection() {
        toggleSidebarSection('#beta-warninglist-content-wrap', '#beta-warninglist-toggle-icon');
    }

    function toggleExportSection() {
        toggleSidebarSection('#beta-export-content-wrap', '#beta-export-toggle-icon');
    }

    function updateTagCount() {
        var count = $('.eventTagContainer .tag-container').length;
        $('#beta-tags-count').text(count);
    }

    function updateGalaxyCount() {
        var count = 0;
        $('#galaxies_div .beta-galaxy-cluster').each(function() {
            count += parseInt($(this).data('cluster-count'), 10) || 1;
        });
        count += $('#galaxies_div .galaxy').length;
        $('#beta-galaxies-count').text(count);
    }

    function updateCollectionsCount() {
        var count = $('#event-collections-container .beta-collection-chip').length;
        $('#beta-collections-count').text(count);
    }

    function updateBetaBulkActionBar() {
        var count = $('.select_attribute:checked').length;
        $('#beta-bulk-selected-count').text(count);
        $('#beta-bulk-actions-bar').toggleClass('is-visible', count > 0);
        $('body').toggleClass('beta-bulk-actions-visible', count > 0);
    }

    window.updateBetaBulkActionBar = updateBetaBulkActionBar;

    function getBetaSelectedAttributeIds() {
        var selected = [];
        $('.select_attribute:checked').each(function() {
            var id = $(this).data('id');
            if (typeof id !== 'undefined' && id !== null && id !== '') {
                selected.push(String(id));
            }
        });
        return selected;
    }

    function getBetaSelectedEntities() {
        var selected = {
            attributes: [],
            objects: []
        };
        $('.select_attribute:checked').each(function() {
            var id = $(this).data('id');
            if (typeof id === 'undefined' || id === null || id === '') {
                return;
            }
            var $row = $(this).closest('tr');
            var objectType = $row.data('object-type');
            if (objectType === 'object') {
                selected.objects.push(String(id));
            } else {
                selected.attributes.push(String(id));
            }
        });
        return selected;
    }

    function clearBetaSelectedAttributes() {
        $('.select_attribute, .select_all, input[class^="select_all_object_attributes_"]').prop('checked', false);
        updateBetaBulkActionBar();
    }

    window.clearBetaSelectedAttributes = clearBetaSelectedAttributes;

    function removeBetaAttributeRows(attributeIds) {
        if (!attributeIds || !attributeIds.length) {
            return;
        }
        attributeIds.forEach(function(attributeId) {
            var selector = '[data-primary-id="' + attributeId + '"]';
            $(selector).remove();
        });
    }

    function refreshBetaAttributeTags(attributeIds) {
        if (!attributeIds || !attributeIds.length || typeof loadAttributeTags !== 'function') {
            return;
        }
        attributeIds.forEach(function(attributeId) {
            loadAttributeTags(attributeId);
        });
    }

    function refreshBetaAttributeGalaxies(attributeIds) {
        if (!attributeIds || !attributeIds.length || typeof loadGalaxies !== 'function') {
            return;
        }
        attributeIds.forEach(function(attributeId) {
            $.ajax({
                dataType: 'html',
                cache: false,
                success: function(data) {
                    var $targets = $('#attribute_' + attributeId + '_galaxy, .beta-attr-galaxies[data-attribute-id="' + attributeId + '"]');
                    if ($targets.length) {
                        $targets.html(data);
                        if (typeof popoverStartup === 'function') {
                            popoverStartup();
                        }
                    }
                },
                url: baseurl + '/galaxies/showGalaxies/' + attributeId + '/attribute'
            });
        });
    }

    function reloadBetaAttributesList() {
        if (typeof window.paginationLoadPage === 'function' && window.paginationState) {
            window.paginationLoadPage(window.paginationState.currentPage, window.paginationState.pageSize);
            return true;
        }
        return false;
    }

    function initBetaSingleDeleteRefresh() {
        if (window._betaSingleDeleteRefreshWrapped || typeof submitDeletion !== 'function') {
            return;
        }
        window._betaSingleDeleteRefreshWrapped = true;
        var originalSubmitDeletion = submitDeletion;
        submitDeletion = function(context_id, action, type, id) {
            if (action !== 'delete' || (type !== 'attributes' && type !== 'objects')) {
                return originalSubmitDeletion.apply(this, arguments);
            }

            var formData = $('#PromptForm').serialize();
            xhr({
                data: formData,
                success: function(data) {
                    var success = handleGenericAjaxResponse(data);
                    if (success) {
                        reloadBetaAttributesList();
                    }
                },
                complete: function() {
                    $('.loading').hide();
                    $('#confirmation_box').fadeOut();
                    $('#gray_out').fadeOut();
                },
                type: 'post',
                url: '/' + type + '/' + action + '/' + id,
            });
        };
    }

    function initBetaMassEditRefresh() {
        if (window._betaMassEditRefreshWrapped || typeof submitPopoverForm !== 'function') {
            return;
        }
        window._betaMassEditRefreshWrapped = true;
        var originalSubmitPopoverForm = submitPopoverForm;
        submitPopoverForm = function(context_id, referer, update_context_id, modal, popover_dismiss_id_to_close) {
            if (referer !== 'massEdit') {
                return originalSubmitPopoverForm.apply(this, arguments);
            }

            var $form = $('#popover_form form').first();
            if (!$form.length) {
                return originalSubmitPopoverForm.apply(this, arguments);
            }

            xhr({
                data: $form.serialize(),
                type: 'post',
                url: $form.attr('action'),
                success: function(data) {
                    var response = data;
                    if (typeof response === 'string') {
                        try {
                            response = JSON.parse(response);
                        } catch (e) {
                            response = null;
                        }
                    }
                    if (response && response.saved) {
                        if (response.success && typeof showMessage === 'function') {
                            showMessage('success', response.success);
                        }
                        $('#popover_form').fadeOut();
                        $('#gray_out').fadeOut();
                        clearBetaSelectedAttributes();
                        reloadBetaAttributesList();
                    } else if (typeof handleGenericAjaxResponse === 'function') {
                        handleGenericAjaxResponse(data);
                    }
                },
                complete: function() {
                    $('.loading').hide();
                }
            });
        };
    }

    function handleBetaBulkDeleteAction(eventId) {
        var selected = getBetaSelectedEntities();
        if (!selected.attributes.length && !selected.objects.length) {
            return false;
        }
        if (!selected.attributes.length && selected.objects.length) {
            showMessage('fail', 'Bulk delete for objects is not supported yet in the beta event view. Use the object dropdown to delete them one by one for now.');
            return false;
        }
        if (selected.objects.length) {
            showMessage('fail', 'Bulk delete of mixed attribute and object selections is not supported in the beta event view. Use the object dropdown to delete objects one by one for now.');
            return false;
        }
        if (typeof window._betaBulkDeleteWrapped === 'undefined') {
            window._betaBulkDeleteWrapped = true;
            var originalHandleGenericAjaxResponse = handleGenericAjaxResponse;
            handleGenericAjaxResponse = function(data, skip_reload) {
                var success = originalHandleGenericAjaxResponse.call(this, data, skip_reload);
                if (success && window._betaPendingBulkDeleteIds && window._betaPendingBulkDeleteIds.length) {
                    removeBetaAttributeRows(window._betaPendingBulkDeleteIds);
                    clearBetaSelectedAttributes();
                    window._betaPendingBulkDeleteIds = null;
                }
                return success;
            };
        }
        window._betaPendingBulkDeleteIds = selected.attributes;
        return multiSelectAction(eventId, 'deleteAttributes');
    }

    function prepareBetaBulkTagRefresh() {
        window._betaPendingBulkTagIds = getBetaSelectedAttributeIds();
    }

    function flushBetaBulkTagRefresh(selectedIds) {
        var attributeIds = selectedIds;
        if (typeof attributeIds === 'string') {
            try {
                attributeIds = JSON.parse(attributeIds);
            } catch (e) {
                attributeIds = [];
            }
        }
        if ((!attributeIds || !attributeIds.length) && window._betaPendingBulkTagIds && window._betaPendingBulkTagIds.length) {
            attributeIds = window._betaPendingBulkTagIds;
        }
        if (attributeIds && attributeIds.length) {
            refreshBetaAttributeTags(attributeIds);
            clearBetaSelectedAttributes();
        }
        window._betaPendingBulkTagIds = null;
    }

    window.onBulkAttributeTagsApplied = function(selectedIds) {
        flushBetaBulkTagRefresh(selectedIds);
    };

    window.onAttributeTagsApplied = function(attributeId) {
        updateBetaAttributeTags(attributeId);
    };

    window.onBulkAttributeGalaxiesApplied = function(selectedIds, local, eventId) {
        var attributeIds = selectedIds;
        if (typeof attributeIds === 'string') {
            try {
                attributeIds = JSON.parse(attributeIds);
            } catch (e) {
                attributeIds = [];
            }
        }
        if (attributeIds && attributeIds.length) {
            refreshBetaAttributeGalaxies(attributeIds);
            if (eventId && typeof loadGalaxies === 'function') {
                loadGalaxies(eventId, 'event');
            }
            clearBetaSelectedAttributes();
        }
    };

    function openBetaBulkTagPicker(isLocal) {
        prepareBetaBulkTagRefresh();
        var tagTarget = (isLocal ? 'local:1/' : '') + 'selected/attribute';
        getPopup(tagTarget, 'tags', 'selectTaxonomy', '', '#popover_form');
    }

    function openBetaBulkGalaxyPicker(isLocal) {
        var galaxyTarget = 'selected/attribute' + (isLocal ? '/local:1' : '/eventid:<?php echo h($event['Event']['id']); ?>');
        if (isLocal) {
            galaxyTarget += '/eventid:<?php echo h($event['Event']['id']); ?>';
        }
        getPopup(galaxyTarget, 'galaxies', 'selectGalaxyNamespace', '', '#popover_form');
    }

    function openBetaGroupIntoObject(eventId, clicked) {
        var selectedAttributeIds = getSelected();
        getPopup(eventId + '/' + selectedAttributeIds, 'objects', 'proposeObjectsFromAttributes', '', '#popover_form');
    }

    function openBetaBulkRelationships(eventId) {
        bulkAddRelationshipToSelectedAttributes(null, eventId);
    }

    function refreshContextCounts() {
        updateTagCount();
        updateGalaxyCount();
        updateCollectionsCount();
    }

    function observeCountContainer(selector, updateFn) {
        if (typeof MutationObserver === 'undefined') {
            return;
        }
        var target = document.querySelector(selector);
        if (!target) {
            return;
        }
        var observer = new MutationObserver(function() {
            updateFn();
        });
        observer.observe(target, { childList: true, subtree: true });
    }

    function initContextCountObservers() {
        if (window._betaContextCountObserversInit) {
            return;
        }
        window._betaContextCountObserversInit = true;
        observeCountContainer('.eventTagContainer', updateTagCount);
        observeCountContainer('#galaxies_div', updateGalaxyCount);
        observeCountContainer('#event-collections-container', updateCollectionsCount);
    }

    function initBetaBulkActions() {
        if (typeof window._betaBulkActionsWrapped === 'undefined') {
            window._betaBulkActionsWrapped = true;

            if (typeof attributeListAnyAttributeCheckBoxesChecked === 'function') {
                var originalAttributeListAnyAttributeCheckBoxesChecked = attributeListAnyAttributeCheckBoxesChecked;
                attributeListAnyAttributeCheckBoxesChecked = function() {
                    var result = originalAttributeListAnyAttributeCheckBoxesChecked.apply(this, arguments);
                    updateBetaBulkActionBar();
                    return result;
                };
            }

            if (typeof toggleAllAttributeCheckboxes === 'function') {
                var originalToggleAllAttributeCheckboxes = toggleAllAttributeCheckboxes;
                toggleAllAttributeCheckboxes = function() {
                    var result = originalToggleAllAttributeCheckboxes.apply(this, arguments);
                    updateBetaBulkActionBar();
                    return result;
                };
            }

            if (typeof toggleAllObjectAttributeCheckboxes === 'function') {
                var originalToggleAllObjectAttributeCheckboxes = toggleAllObjectAttributeCheckboxes;
                toggleAllObjectAttributeCheckboxes = function() {
                    var result = originalToggleAllObjectAttributeCheckboxes.apply(this, arguments);
                    updateBetaBulkActionBar();
                    return result;
                };
            }
        }

        $(document)
            .off('change.betaBulkActions')
            .on('change.betaBulkActions', '.select_attribute, .select_all, input[class^="select_all_object_attributes_"]', function() {
                setTimeout(updateBetaBulkActionBar, 0);
            });

        updateBetaBulkActionBar();
    }

    window.initBetaBulkActions = initBetaBulkActions;

    function closeBetaBulkMenus() {
        $('[data-beta-bulk-menu]').removeClass('is-open');
        $('[data-beta-bulk-menu-panel]').removeClass('is-open');
        $('[data-beta-bulk-menu-trigger]').attr('aria-expanded', 'false');
    }

    function toggleBetaBulkMenu(trigger) {
        var $wrap = $(trigger).closest('[data-beta-bulk-menu]');
        var $panel = $wrap.find('[data-beta-bulk-menu-panel]');
        var shouldOpen = !$panel.hasClass('is-open');
        closeBetaBulkMenus();
        if (shouldOpen) {
            $wrap.addClass('is-open');
            $panel.addClass('is-open');
            $wrap.find('[data-beta-bulk-menu-trigger]').attr('aria-expanded', 'true');
        }
    }

    // Export card logic
    var betaExportFormats = <?php
        $betaExportFormatsJs = [];
        foreach ($betaExportFormats as $k => $fmt) {
            $betaExportFormatsJs[$k] = [
                'url' => $fmt['url'],
                'checkbox' => !empty($fmt['checkbox']),
                'checkbox_label' => isset($fmt['checkbox_label']) ? $fmt['checkbox_label'] : '',
                'checkbox_url' => isset($fmt['checkbox_url']) ? $fmt['checkbox_url'] : '',
            ];
        }
        echo json_encode($betaExportFormatsJs);
    ?>;

    function exportFormatChanged(key) {
        var fmt = betaExportFormats[key];
        if (!fmt) return;
        var $row = $('#beta-export-checkbox-row');
        var $label = $('#beta-export-checkbox-label');
        var $cb = $('#beta-export-checkbox');
        if (fmt.checkbox && fmt.checkbox_label) {
            $label.text(fmt.checkbox_label);
            $cb.prop('checked', false);
            $row.show();
        } else {
            $row.hide();
            $cb.prop('checked', false);
        }
    }

    function exportDownload() {
        var key = $('#beta-export-format').val();
        var fmt = betaExportFormats[key];
        if (!fmt) return;
        var url = fmt.url;
        if (fmt.checkbox && $('#beta-export-checkbox').prop('checked') && fmt.checkbox_url) {
            url = fmt.checkbox_url;
        }
        window.location.href = url;
    }

    function clearAttributeFilter() {
        $('.filter-active-msg').remove();
        if (typeof paginationState !== 'undefined') {
            paginationState.searchActive = false;
            paginationState.attributeType = '';
            $('.beta-pagination-container').show();
            if (typeof window.paginationLoadPage === 'function') {
                window.paginationLoadPage(1, window.paginationState.pageSize);
            } else {
                $('.beta-attr-row').show();
            }
        } else {
            $('.beta-attr-row').show();
        }
    }

    function filterAttributesByComposition(type, name) {
        // Switch to Attributes tab
        $('.nav-tabs a[href="#attributes"]').tab('show');

        $('.filter-active-msg').remove();

        if (type === 'attribute' && typeof paginationState !== 'undefined' && typeof window.paginationLoadPage === 'function') {
            paginationState.searchActive = false;
            paginationState.attributeType = name;
            $('.beta-pagination-container').show();
            window.paginationLoadPage(1, paginationState.pageSize);
        } else {
            // Fallback for non-attribute data
            $('.beta-attr-row').show();
            $('.beta-attr-row').hide();
            if (type === 'object') {
                $('.beta-attr-row[data-object-name="' + name + '"]').show();
                $('.beta-attr-row[data-parent-object="' + name + '"]').show();
            } else {
                $('.beta-attr-row[data-attribute-type="' + name + '"]').show();
            }
        }

        renderFilterMessage(
            buildFilterMessage('Filtering by <strong>' + (type === 'object' ? 'Object: ' : 'Attribute: ') + name + '</strong>'),
            '#beta-filter-banner-slot'
        );
    }

    // Auto-resize report preview iframe based on content height
    <?php if (!empty($firstEventReportId)): ?>
    window.summaryReportExpanded = false;
    window.summaryReportContentHeight = 0;

    function getReportPreviewMaxHeight() {
        if (!window.summaryReportExpanded) {
            return 300;
        }
        var iframe = document.getElementById('summary-report-iframe');
        if (!iframe) {
            return Math.max(window.innerHeight - 40, 300);
        }
        var rect = iframe.getBoundingClientRect();
        var viewportBottomPadding = 104;
        return Math.max(window.innerHeight - rect.top - viewportBottomPadding, 300);
    }

    function applyReportPreviewHeight() {
        var iframe = document.getElementById('summary-report-iframe');
        if (!iframe) {
            return;
        }
        var maxHeight = getReportPreviewMaxHeight();
        var targetHeight = window.summaryReportExpanded
            ? maxHeight
            : Math.min(window.summaryReportContentHeight + 10, maxHeight);
        iframe.style.height = Math.max(targetHeight, 120) + 'px';
    }

    function refreshReportPreviewHeight() {
        window.setTimeout(function() {
            applyReportPreviewHeight();
        }, 0);
        window.setTimeout(function() {
            applyReportPreviewHeight();
        }, 120);
    }

    function toggleReportPreviewSize() {
        window.summaryReportExpanded = !window.summaryReportExpanded;
        var expandToggle = document.getElementById('summary-report-expand-toggle');
        var expandIcon = document.getElementById('summary-report-expand-icon');
        if (expandToggle) {
            var expandLabel = expandToggle.getAttribute('data-expand-label') || 'Expand preview';
            var collapseLabel = expandToggle.getAttribute('data-collapse-label') || 'Collapse preview';
            var label = window.summaryReportExpanded ? collapseLabel : expandLabel;
            expandToggle.setAttribute('aria-label', label);
            expandToggle.setAttribute('title', label);
        }
        if (expandIcon) {
            expandIcon.className = window.summaryReportExpanded ? 'fa fa-angle-double-up' : 'fa fa-angle-double-down';
        }
        applyReportPreviewHeight();
    }

    window.addEventListener('message', function(event) {
        if (event.data && event.data.type === 'reportPreviewResize') {
            window.summaryReportContentHeight = parseInt(event.data.height, 10) || 0;
            applyReportPreviewHeight();
        }
    });

    window.addEventListener('resize', function() {
        refreshReportPreviewHeight();
    });
    <?php endif; ?>

    function toggleAnalysisLinks() {
        var toggle = document.getElementById('analysis-links-toggle');
        if (!toggle) {
            return;
        }
        var expanded = toggle.getAttribute('data-expanded') === '1';
        var items = document.querySelectorAll('.analysis-link-item-extra');
        for (var i = 0; i < items.length; i++) {
            items[i].style.display = expanded ? 'none' : '';
        }
        var showMoreLabel = toggle.getAttribute('data-show-more-label') || 'Show all';
        var showLessLabel = toggle.getAttribute('data-show-less-label') || 'Show less';
        var hiddenCount = parseInt(toggle.getAttribute('data-hidden-count'), 10) || 0;
        toggle.textContent = expanded ? (showMoreLabel + ' (' + hiddenCount + ' <?php echo h(__('more')); ?>)') : showLessLabel;
        toggle.setAttribute('data-expanded', expanded ? '0' : '1');
    }

    function applyCommentAttributeFilter(comment) {
        $('.filter-active-msg').remove();
        $('#beta-attr-search').val(comment).trigger('keyup');

        var filterMessage = buildFilterMessage('Filtering by Comment: <strong>' + escapeHtml(comment) + '</strong>');
        if ($('.beta-toolbar').length) {
            $('.beta-toolbar').after(filterMessage);
        } else {
            renderFilterMessage(filterMessage, '');
        }
    }

    function filterAttributesByComment(comment) {
        var $attributesTab = $('.nav-tabs a[href="#attributes"]');
        if (!$attributesTab.length) {
            return;
        }

        if ($('#attributes').hasClass('active')) {
            applyCommentAttributeFilter(comment);
            return;
        }

        $attributesTab.one('shown.bs.tab.commentFilter', function () {
            applyCommentAttributeFilter(comment);
        });
        $attributesTab.tab('show');
    }

    function toggleSummaryReports(forceOpen) {
        var $wrap = $('#summary-reports-content-wrap');
        if (!$wrap.length) return;

        var open = (typeof forceOpen === 'boolean') ? forceOpen : !$wrap.is(':visible');
        var $icon = $('#summary-reports-toggle-icon');

        if (open) {
            $wrap.stop(true, true).slideDown(140);
            $icon.removeClass('fa-chevron-right').addClass('fa-chevron-down');
        } else {
            $wrap.stop(true, true).slideUp(140);
            $icon.removeClass('fa-chevron-down').addClass('fa-chevron-right');
        }
    }

    var _correlationData = null;
    var _correlationEventDetails = null;
    var _correlationsLoading = false;
    var _currentEventDate = '<?php echo addslashes(h($event['Event']['date'])); ?>';
    var _currentEventDateTs = _currentEventDate ? Date.parse(_currentEventDate + 'T00:00:00Z') : NaN;

    function formatTimelineDateUtc(ts) {
        var d = new Date(ts);
        var y = d.getUTCFullYear();
        var m = String(d.getUTCMonth() + 1).padStart(2, '0');
        var day = String(d.getUTCDate()).padStart(2, '0');
        return y + '-' + m + '-' + day;
    }

    function highlightCorrelationCard(eventId) {
        if (!eventId) return;
        $('.beta-correlation-card-highlight').removeClass('beta-correlation-card-highlight');
        var $card = $('.correlation-event-card[data-event-id="' + String(eventId).replace(/"/g, '\\"') + '"]').first();
        if (!$card.length) return;
        $card.addClass('beta-correlation-card-highlight');
        $('html, body').animate({
            scrollTop: Math.max($card.offset().top - 120, 0)
        }, 350);
        window.setTimeout(function() {
            $card.removeClass('beta-correlation-card-highlight');
        }, 1400);
    }

    function renderCorrelationsTimeline(detailsMap) {
        var timeline = document.getElementById('correlationsEventTimeline');
        if (!timeline) return;

        var markers = timeline.querySelector('.beta-event-timeline-markers');
        var ticks = timeline.querySelector('.beta-event-timeline-ticks');
        var rangeLabel = document.getElementById('correlationsEventTimelineRange');
        if (!markers || !ticks) return;

        var items = Object.keys(detailsMap || {}).map(function(eid) {
            var details = detailsMap[eid] || {};
            var date = details.date || '';
            var ts = Date.parse(date + 'T00:00:00Z');
            if (!date || !isFinite(ts)) {
                return null;
            }
            return {
                id: eid,
                title: details.info || '',
                date: date,
                ts: ts
            };
        }).filter(function(item) { return item !== null; });

        if (!items.length) {
            timeline.style.display = 'none';
            return;
        }

        items.sort(function(a, b) { return a.ts - b.ts; });
        var itemMinTs = items[0].ts;
        var itemMaxTs = items[items.length - 1].ts;
        var minTs = itemMinTs;
        var maxTs = itemMaxTs;
        if (isFinite(_currentEventDateTs)) {
            minTs = Math.min(minTs, _currentEventDateTs);
            maxTs = Math.max(maxTs, _currentEventDateTs);
        }
        var rawRange = maxTs - minTs;
        var range = Math.max(rawRange, 1);

        ticks.innerHTML = '';
        var tickCount = rawRange === 0 ? 1 : Math.min(7, Math.max(3, items.length + 1));
        for (var i = 0; i < tickCount; i++) {
            var tick = document.createElement('span');
            var pctTick = tickCount === 1 ? 50 : (i / (tickCount - 1)) * 100;
            var isEdgeTick = i === 0 || i === tickCount - 1;
            tick.className = 'beta-event-timeline-tick' + (isEdgeTick ? ' beta-event-timeline-tick-edge' : '');
            tick.style.left = pctTick + '%';

            var tickTs = rawRange === 0 ? minTs : minTs + ((range * i) / Math.max(1, tickCount - 1));
            var label = document.createElement('span');
            label.className = 'beta-event-timeline-tick-label';
            if (i === 0) {
                label.className += ' beta-event-timeline-tick-label-start';
            } else if (i === tickCount - 1) {
                label.className += ' beta-event-timeline-tick-label-end';
            }
            label.textContent = formatTimelineDateUtc(tickTs);
            tick.appendChild(label);
            ticks.appendChild(tick);
        }

        markers.innerHTML = '';
        if (isFinite(_currentEventDateTs)) {
            var currentMarker = document.createElement('span');
            currentMarker.className = 'beta-event-timeline-current-marker';
            currentMarker.style.left = (range > 0 ? ((_currentEventDateTs - minTs) / range) * 100 : 50) + '%';
            currentMarker.setAttribute('aria-hidden', 'true');
            markers.appendChild(currentMarker);

            var currentLabel = document.createElement('span');
            currentLabel.className = 'beta-event-timeline-current-label';
            currentLabel.style.left = currentMarker.style.left;
            currentLabel.textContent = '★ <?php echo addslashes(__('This Event')); ?>';
            currentLabel.setAttribute('aria-hidden', 'true');
            markers.appendChild(currentLabel);
        }
        items.forEach(function(item) {
            var marker = document.createElement('button');
            marker.type = 'button';
            marker.className = 'beta-event-timeline-marker';
            marker.style.left = (range > 0 ? ((item.ts - minTs) / range) * 100 : 50) + '%';
            marker.title = (item.title || 'Event #' + item.id) + ' - ' + item.date;
            marker.setAttribute('data-event-id', item.id);
            marker.setAttribute('aria-label', 'Open correlated event #' + item.id + ' on timeline');
            markers.appendChild(marker);
        });

        if (rangeLabel) {
            var start = formatTimelineDateUtc(itemMinTs);
            var end = formatTimelineDateUtc(maxTs);
            rangeLabel.textContent = start === end ? start : (start + ' → ' + end);
        }

        timeline.style.display = '';
        updateCorrelationsTimelineVisibility();
        markers.onclick = function(e) {
            var target = e.target.closest('.beta-event-timeline-marker');
            if (!target) return;
            highlightCorrelationCard(target.getAttribute('data-event-id'));
        };
    }

    function loadCorrelations() {
        if (_correlationData !== null || _correlationsLoading) return;
        _correlationsLoading = true;
        var eventId = '<?php echo h($event['Event']['id']); ?>';
        $.ajax({
            url: '<?php echo $baseurl; ?>/correlations/eventCorrelations/' + eventId + '.json?include_attributes=1&include_org_names=1',
            type: 'GET',
            success: function(response) {
                _correlationsLoading = false;
                $('#correlations-loader').hide();
                $('#correlations-content').show();
                renderCorrelations(response);
                // Apply any pending filter
                if (_pendingCorrelationFilter !== null) {
                    var pendingFilter = _pendingCorrelationFilter;
                    _pendingCorrelationFilter = null;
                    _applyCorrelationFilter(pendingFilter.value, pendingFilter.type);
                    $('html, body').animate({
                        scrollTop: $(".beta-tabs-container").offset().top
                    }, 500);
                }
            },
            error: function() {
                _correlationsLoading = false;
                $('#correlations-loader').html('<p class="text-danger"><?php echo __('Failed to load correlations.'); ?></p>');
            }
        });
    }

    function buildCorrelationCommentHtml(comment) {
        if (!comment) {
            return '';
        }
        var iconHtml = '<i class="fa fa-comment"></i>';
        var safeComment = escapeHtml(comment);
        var safeCommentAttr = safeComment.replace(/"/g, '&quot;');
        if (comment.length > 50) {
            return '<span class="beta-correlation-comment-inline">'
                + iconHtml
                + '<span>' + escapeHtml(comment.substring(0, 50)) + '...</span>'
                + '<i class="fa fa-comment-dots" style="cursor: pointer;" data-toggle="popover" data-trigger="click" data-placement="top" data-content="' + safeCommentAttr + '"></i>'
                + '</span>';
        }
        return '<span class="beta-correlation-comment-inline">'
            + iconHtml
            + '<span>' + safeComment + '</span>'
            + '</span>';
    }

    function buildFilteredCorrelationCommentChip(entry) {
        if (!entry || !entry.comment) {
            return '';
        }
        var eventId = entry.eventId ? String(entry.eventId) : '';
        var isCurrentEvent = entry.isCurrentEvent ? '1' : '0';
        var safeComment = $('<div/>').text(entry.comment).html();
        var safeTitle = $('<div/>').text(entry.title || entry.comment).html();
        return '<button type="button" class="beta-correlation-filter-comment-chip" data-event-id="' + eventId.replace(/"/g, '&quot;') + '" data-current-event="' + isCurrentEvent + '" title="' + safeTitle + '">'
            + '<i class="fa fa-comment"></i>'
            + '<span>' + safeComment + '</span>'
            + '</button>';
    }

    function scrollToCorrelationCommentTarget(eventId, isCurrentEvent) {
        var $target = $();
        if (isCurrentEvent) {
            $target = $('#correlations-this-event-card');
        }
        if (!$target.length && eventId) {
            $target = $('.correlation-event-card[data-event-id="' + String(eventId).replace(/"/g, '\\"') + '"]').first();
        }
        if (!$target.length) {
            return;
        }
        $('.beta-correlation-card-highlight').removeClass('beta-correlation-card-highlight');
        $target.addClass('beta-correlation-card-highlight');
        $('html, body').animate({
            scrollTop: Math.max($target.offset().top - 120, 0)
        }, 350);
        window.setTimeout(function() {
            $target.removeClass('beta-correlation-card-highlight');
        }, 1400);
    }

    function renderCorrelations(data) {
            _correlationData = data;
            var eventCounts = {};
            var eventDetails = {};
            var attributeMap = {};

            function buildCorrelationEventHeader(eid, details, count, percent, creatorOrg) {
                var html = '';
                html += '  <div class="beta-card-header" style="display: flex; justify-content: space-between; align-items: center; gap: 16px;">';
                html += '    <div style="display: flex; align-items: center; gap: 10px;">';
                html += '      <span class="label label-default" style="font-weight: normal;">' + escapeHtml(details.date) + '</span>';
                if (creatorOrg) {
                    html += '      <span class="beta-correlation-org"><i class="fa fa-building"></i>' + creatorOrg + '</span>';
                }
                html += '      <a class="beta-correlation-event-link" href="<?php echo $baseurl; ?>/events/view/' + eid + '">#' + eid + ' ' + escapeHtml(details.info) + '</a>';
                html += '    </div>';
                html += '    <div style="text-align: right;">';
                html += '      <span style="font-size: 12px; font-weight: 600; color: #666;">' + count + ' ' + (count === 1 ? 'match' : 'matches') + '</span>';
                html += '      <div style="width: 100px; height: 4px; background: #eee; border-radius: 2px; margin-top: 4px;">';
                html += '        <div style="width: ' + percent + '%; height: 100%; background: #428bca; border-radius: 2px;"></div>';
                html += '      </div>';
                html += '    </div>';
                html += '  </div>';
                return html;
            }

            function buildCorrelationAttributeHref(eid, attr) {
                var focusUuid = '';
                if (attr.Object && attr.Object.uuid) {
                    focusUuid = attr.Object.uuid;
                } else if (attr.uuid) {
                    focusUuid = attr.uuid;
                }
                var attrAnchor = attr.id ? ('#Attribute_' + attr.id + '_tr') : '#attributes';
                if (focusUuid) {
                    return '<?php echo $baseurl; ?>/events/view/' + eid + '/focus:' + encodeURIComponent(focusUuid) + attrAnchor;
                }
                if (attr.id) {
                    return '<?php echo $baseurl; ?>/events/view/' + eid + '#Attribute_' + attr.id + '_tr';
                }
                return '';
            }

            function buildCorrelationTagHtml(tag) {
                var tagColor = tag.colour || '#0088cc';
                var hex = tagColor.replace('#', '');
                var r, g, b;
                if (hex.length === 3) {
                    r = parseInt(hex[0] + hex[0], 16);
                    g = parseInt(hex[1] + hex[1], 16);
                    b = parseInt(hex[2] + hex[2], 16);
                } else {
                    r = parseInt(hex.substring(0, 2), 16);
                    g = parseInt(hex.substring(2, 4), 16);
                    b = parseInt(hex.substring(4, 6), 16);
                }
                var rgba = 'rgba(' + r + ', ' + g + ', ' + b + ', 0.7)';
                var luminance = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
                var iconColor = luminance > 0.5 ? '#000' : '#fff';

                var html = '';
                html += '<div class="tag-container tag-wrapper-beta" style="display: inline-flex; align-items: stretch; margin-right: 4px; margin-bottom: 2px;">';
                html += '  <span class="tag-scope-icon" style="background-color: ' + rgba + '; color: ' + iconColor + '; display: inline-flex; align-items: center; justify-content: center; padding: 4px 6px; border-radius: 4px 0 0 4px; border: 1px solid #d0d0d0; border-right: none;"><i class="fas fa-' + (tag.local ? 'user' : 'globe-americas') + '" style="font-size: 11px;"></i></span>';
                html += '  <span class="tag nowrap" style="background-color: transparent; border: 1px solid #d0d0d0; color: #000; padding: 3px 8px; font-size: 12px; border-radius: 0 4px 4px 0;">' + escapeHtml(tag.name) + '</span>';
                html += '</div>';
                return html;
            }

            function buildCorrelationAttributeRow(eid, entry) {
                var attr = entry.attribute;
                if (!attr) {
                    return '        <tr class="beta-attr-row">'
                        + '          <td style="width: 40px;"></td>'
                        + '          <td colspan="5"><span class="label label-info">' + escapeHtml(entry.value) + '</span></td>'
                        + '        </tr>';
                }

                var html = '';
                var linkHref = buildCorrelationAttributeHref(eid, attr);
                html += '        <tr class="beta-correlation-row" data-attribute-id="' + entry.id + '">';
                html += '          <td class="beta-correlation-anchor-cell"><i class="fa fa-link"></i></td>';
                html += '          <td colspan="2">';
                html += '            <div class="beta-correlation-meta">';
                html += '              <div class="beta-attr-type-path">';
                html += '                <span class="beta-correlation-chevrons">';
                html += '                  <span class="beta-correlation-chevron beta-correlation-category"><span>' + escapeHtml(attr.category) + '</span></span>';
                if (attr.Object && attr.Object.name) {
                    html += '                  <span class="beta-correlation-chevron beta-correlation-relation"><span>' + escapeHtml(attr.Object.name) + '</span></span>';
                    if (attr.object_relation) {
                        html += '                  <span class="beta-correlation-chevron beta-correlation-relation"><span>' + escapeHtml(attr.object_relation) + '</span></span>';
                    }
                }
                html += '                  <span class="beta-correlation-chevron beta-correlation-type"><span>' + escapeHtml(attr.type) + '</span></span>';
                html += '                </span>';
                if (attr.comment) {
                    html += '                ' + buildCorrelationCommentHtml(attr.comment);
                }
                html += '              </div>';
                html += '              <div class="beta-correlation-value-row">';
                if (attr.uuid || attr.id) {
                    html += '                <a class="beta-correlation-value-link" href="' + linkHref + '" title="<?php echo h(__('Open attribute in related event')); ?>">' + escapeHtml(attr.value) + '</a>';
                    html += '                <a class="beta-correlation-branch-link" href="' + linkHref + '" title="<?php echo h(__('Open attribute in related event')); ?>"><i class="fa fa-code-branch"></i></a>';
                } else {
                    html += '                <span class="beta-correlation-value-link">' + escapeHtml(attr.value) + '</span>';
                }
                html += '              </div>';
                if (attr.AttributeTag && attr.AttributeTag.length > 0) {
                    html += '              <div class="beta-correlation-inline-tags">';
                    attr.AttributeTag.forEach(function(at) {
                        html += buildCorrelationTagHtml(at.Tag);
                    });
                    html += '              </div>';
                }
                html += '            </div>';
                html += '          </td>';
                html += '          <td class="col-related"></td>';
                html += '          <td style="text-align: center;">';
                html += '            <i class="fa fa-shield-alt beta-correlation-status-icon ' + (attr.to_ids ? 'is-ids-active' : '') + '" style="font-size: 1.5em; ' + (attr.to_ids ? '' : 'opacity: 0.22;') + '" title="' + (attr.to_ids ? 'Recommended for blocking / alerting' : 'Not recommended for blocking / alerting') + '"></i>';
                html += '          </td>';
                html += '          <td class="col-correlation" style="text-align: center;">';
                html += '            <i class="fa fa-project-diagram beta-correlation-status-icon ' + (attr.disable_correlation ? '' : 'is-correlation-active') + '" style="' + (attr.disable_correlation ? 'opacity: 0.22;' : '') + '" title="' + (attr.disable_correlation ? 'Correlation disabled' : 'Correlation enabled') + '"></i>';
                html += '          </td>';
                html += '          <td class="col-sightings" style="text-align: center;"><i class="fa fa-eye beta-correlation-status-icon" style="opacity: 0.24;"></i></td>';
                html += '          <td class="col-distribution beta-correlation-distribution-cell">';
                var sharingGroupName = (attr.SharingGroup && attr.SharingGroup.name) || '';
                html += '            <div class="dist-widget dist-' + parseInt(attr.distribution, 10) + '" title="' + escapeHtml(sharingGroupName).replace(/"/g, '&quot;') + '"></div>';
                html += '          </td>';
                html += '          <td class="col-date beta-correlation-date-cell" style="width: 90px;"><span class="beta-correlation-date-text">' + moment.unix(attr.timestamp).format('YYYY-MM-DD') + '</span></td>';
                html += '        </tr>';
                return html;
            }

            // Process data
            for (var parentId in data) {
                var relations = data[parentId];
                relations.forEach(function(rel) {
                    var eid = rel.id;
                    if (!eventCounts[eid]) {
                        eventCounts[eid] = 0;
                        eventDetails[eid] = {info: rel.info, date: rel.date, org: rel.org_id, orgName: rel.org_name || ''};
                    }
                    eventCounts[eid]++;
                    
                    if (!attributeMap[eid]) attributeMap[eid] = [];
                    attributeMap[eid].push({
                        id: parentId,
                        value: rel.value || parentId, // Fallback to ID if value not present
                        type: rel.type || '',
                        attribute: rel.Attribute || null
                    });
                });
            }

            var sortedEvents = Object.keys(eventCounts).sort(function(a,b){return eventCounts[b]-eventCounts[a]});
            if (sortedEvents.length === 0) {
                $('#correlations-table-container').html('<p class="muted"><?php echo __('No correlations found.'); ?></p>');
                return;
            }

            var max = eventCounts[sortedEvents[0]];
            var html = '<div class="beta-correlations-container">';
            
            sortedEvents.forEach(function(eid) {
                var count = eventCounts[eid];
                var details = eventDetails[eid];
                var percent = (count / max) * 100;
                var attrs = attributeMap[eid];
                var attrIds = attrs.map(function(a) { return a.id; }).join(',');
                var creatorOrg = details.orgName ? $('<div/>').text(details.orgName).html() : '';
                
                html += '<div class="beta-card correlation-event-card" data-event-id="' + eid + '" data-org-id="' + (details.org || '') + '" data-org-name="' + creatorOrg.replace(/"/g, '&quot;') + '" data-attribute-ids=",' + attrIds + '," style="margin-bottom: 20px; border-left: 4px solid #428bca;">';
                html += buildCorrelationEventHeader(eid, details, count, percent, creatorOrg);
                html += '  <div class="beta-card-body" style="padding: 0;">';
                html += '    <table class="beta-attr-table" style="margin-top: 0;">';
                html += '      <tbody>';
                
                attrs.forEach(function(a) {
                    html += buildCorrelationAttributeRow(eid, a);
                });
                
                html += '      </tbody>';
                html += '    </table>';
                html += '  </div>';
                html += '</div>';
            });
            
            html += '</div>';
            $('#correlations-table-container').html(html);
            
            _correlationEventDetails = eventDetails;
            _correlationAttributeMap = attributeMap;
            renderCorrelationsTimeline(eventDetails);
            renderSankey(data, eventDetails);
        }

        function renderSankey(data, eventDetails, filterAttributeId, options) {
            options = options || {};
            var nodes = [];
            var links = [];
            var nodeMap = {};
            var orgNodeByTargetEventId = {};
            var filterOrgId = options.filterOrgId || null;
            var alignToDate = $('#sankey-date-align-toggle').is(':checked');
            var latestEventsOnly = $('#sankey-latest-events-toggle').is(':checked');
            var showPublisher = $('#sankey-show-publisher-toggle').is(':checked');
            var latestEventsLimit = 20;
            var currentEventId = '<?php echo h($event['Event']['id']); ?>';
            var currentEventInfo = '<?php echo addslashes(h($event['Event']['info'])); ?>';
            var currentEventName = currentEventInfo || ('Event #' + currentEventId);
            var currentEventDate = '<?php echo addslashes(h($event['Event']['date'])); ?>';
            var currentEventFullTitle = 'Event #' + currentEventId;
            if (currentEventDate) {
                currentEventFullTitle += ' (' + currentEventDate + ')';
            }
            if (currentEventInfo) {
                currentEventFullTitle += ': ' + currentEventInfo;
            }
            var $sankeyShell = $('#correlations-sankey-shell');
            
            function addNode(name, type, id, fullTitle) {
                var key = name + '_' + type;
                if (nodeMap[key] === undefined) {
                    nodeMap[key] = nodes.length;
                    nodes.push({name: name, type: type, id: id, fullTitle: fullTitle});
                }
                return nodeMap[key];
            }

            var sourceIdx = addNode(currentEventName, 'source', currentEventId, currentEventFullTitle);
            
            // If a filter is active, only show the filtered attribute; otherwise limit to top correlations
            var maxSankeyAttributes = 100;
            var parentIds;
            if (filterAttributeId) {
                // Only include the filtered attribute if it exists in data
                parentIds = Object.keys(data).filter(function(id) { return id == filterAttributeId; });
            } else {
                parentIds = Object.keys(data).sort(function(a, b) {
                    return data[b].length - data[a].length;
                });
            }
            
            var totalAttributes = parentIds.length;
            if (!filterAttributeId && parentIds.length > maxSankeyAttributes) {
                parentIds = parentIds.slice(0, maxSankeyAttributes);
            }

            var allowedTargetEventIds = null;
            if (latestEventsOnly) {
                var latestTargetEvents = [];
                var latestTargetEventSeen = {};
                parentIds.forEach(function(parentId) {
                    (data[parentId] || []).forEach(function(rel) {
                        if (latestTargetEventSeen[rel.id]) {
                            return;
                        }
                        latestTargetEventSeen[rel.id] = true;
                        var details = eventDetails && eventDetails[rel.id] ? eventDetails[rel.id] : null;
                        var eventDate = rel.date || (details && details.date) || '';
                        var eventDateTs = eventDate ? Date.parse(eventDate + 'T00:00:00Z') : NaN;
                        latestTargetEvents.push({
                            id: String(rel.id),
                            dateTs: isFinite(eventDateTs) ? eventDateTs : -Infinity
                        });
                    });
                });
                latestTargetEvents.sort(function(a, b) {
                    if (b.dateTs !== a.dateTs) {
                        return b.dateTs - a.dateTs;
                    }
                    return String(b.id).localeCompare(String(a.id), undefined, {numeric: true});
                });
                allowedTargetEventIds = {};
                latestTargetEvents.slice(0, latestEventsLimit).forEach(function(item) {
                    allowedTargetEventIds[item.id] = true;
                });
            }

            var eventLinkCounts = {};
            if (eventDetails) {
                for (var eid in eventDetails) {
                    eventLinkCounts[eid] = 0;
                }
            }
            
            // Calculate how many attributes lead to each event
            parentIds.forEach(function(parentId) {
                var relations = data[parentId];
                relations.forEach(function(rel) {
                    if (allowedTargetEventIds && !allowedTargetEventIds[String(rel.id)]) {
                        return;
                    }
                    if (eventLinkCounts[rel.id] !== undefined) {
                        eventLinkCounts[rel.id]++;
                    } else {
                        eventLinkCounts[rel.id] = 1;
                    }
                });
            });

            parentIds.forEach(function(parentId) {
                var relations = data[parentId];
                var filteredRelations = relations.filter(function(rel) {
                    if (allowedTargetEventIds && !allowedTargetEventIds[String(rel.id)]) {
                        return false;
                    }
                    if (filterOrgId) {
                        var relOrgId = rel.org_id || (eventDetails && eventDetails[rel.id] && eventDetails[rel.id].org) || 'unknown';
                        return String(relOrgId) === String(filterOrgId);
                    }
                    return true;
                });
                if (!filteredRelations.length) {
                    return;
                }
                var attrValue = relations[0].value || ('Attr #' + parentId);
                var attrIdx = addNode(attrValue, 'attribute', parentId);

                links.push({
                    source: sourceIdx,
                    target: attrIdx,
                    value: filteredRelations.length
                });

                filteredRelations.forEach(function(rel) {
                    var count = eventLinkCounts[rel.id] || 1;
                    var rawTargetName = rel.info || ('#' + rel.id);
                    var shortTargetName = rawTargetName.length > 56 ? rawTargetName.substring(0, 53) + '...' : rawTargetName;
                    var targetEventName = count > 1 ? '(' + count + ') ' + shortTargetName : shortTargetName;
                    var relDate = rel.date || '';
                    var relOrgName = rel.org_name || (eventDetails && eventDetails[rel.id] && eventDetails[rel.id].orgName) || '<?php echo addslashes(__('Unknown source')); ?>';
                    var fullTitle = count > 1 ? '(' + count + ') ' + rawTargetName : rawTargetName;
                    if (relDate) {
                        fullTitle += ' (' + relDate + ')';
                    }
                    if (relOrgName) {
                        fullTitle += ' | ' + '<?php echo addslashes(__('Publisher')); ?>' + ': ' + relOrgName;
                    }
                    var targetIdx = addNode(targetEventName, 'target', rel.id, fullTitle);
                    if (showPublisher && orgNodeByTargetEventId[rel.id] === undefined) {
                        var relOrgId = rel.org_id || (eventDetails && eventDetails[rel.id] && eventDetails[rel.id].org) || 'unknown';
                        orgNodeByTargetEventId[rel.id] = addNode(relOrgName, 'org', relOrgId, relOrgName);
                    }
                    
                    links.push({
                        source: attrIdx,
                        target: targetIdx,
                        value: 1
                    });
                });
            });

            if (showPublisher) {
                Object.keys(orgNodeByTargetEventId).forEach(function(eventId) {
                    var targetNodeIndex = null;
                    var orgNodeIndex = orgNodeByTargetEventId[eventId];
                    for (var i = 0; i < nodes.length; i++) {
                        if (nodes[i].type === 'target' && String(nodes[i].id) === String(eventId)) {
                            targetNodeIndex = i;
                            break;
                        }
                    }
                    if (targetNodeIndex !== null && orgNodeIndex !== undefined) {
                        links.push({
                            source: targetNodeIndex,
                            target: orgNodeIndex,
                            value: 1
                        });
                    }
                });
            }

            var displayedEventsNodeIds = {};
            links.forEach(function(l) {
                if (nodes[l.target] && nodes[l.target].type === 'target') {
                    displayedEventsNodeIds[nodes[l.target].id] = true;
                }
            });
            var totalDisplayedEvents = Object.keys(displayedEventsNodeIds).length;
            var totalPossibleEvents = Object.keys(eventDetails || {}).length;

            if (totalPossibleEvents > totalDisplayedEvents) {
                $('#sankey-limit-msg').text('<?php echo __("Showing top %s of %s correlating events", "' + totalDisplayedEvents + '", "' + totalPossibleEvents + '"); ?>');
            } else {
                $('#sankey-limit-msg').text('<?php echo __("Showing %s correlating events", "' + totalDisplayedEvents + '"); ?>');
            }

            if (links.length === 0) return;
            $('#correlations-sankey-stage').show();

            function truncateSourceLabel(name) {
                var sourceVisibleChars = 30;
                return name.length > sourceVisibleChars ? name.substring(0, sourceVisibleChars) + '...' : name;
            }

            function estimateLabelWidth(chars, charWidth, minWidth, maxWidth) {
                var widthEstimate = (chars * charWidth);
                return Math.max(minWidth, Math.min(maxWidth, widthEstimate));
            }

            var $sankeyStage = $('#correlations-sankey-stage');
            var viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
            var stageWidth = Math.max($sankeyStage.innerWidth() || 0, $('#correlations-sankey').width() || 0);
            var stageRect = $sankeyStage.length ? $sankeyStage[0].getBoundingClientRect() : null;
            var viewportPadding = stageRect ? Math.max(stageRect.left || 0, viewportWidth - (stageRect.right || viewportWidth), 12) : 12;
            var containerWidth = Math.max(720, Math.min(stageWidth || viewportWidth, viewportWidth - (viewportPadding * 2)));
            var sourceLabelText = '★ ' + truncateSourceLabel(currentEventName);
            var longestTargetLabelLength = 0;
            var longestOrgLabelLength = 0;
            nodes.forEach(function(node) {
                if (node.type === 'target') {
                    longestTargetLabelLength = Math.max(longestTargetLabelLength, (node.name || '').length);
                } else if (node.type === 'org') {
                    longestOrgLabelLength = Math.max(longestOrgLabelLength, (node.name || '').length);
                }
            });

            var sourceLabelBudget = estimateLabelWidth(sourceLabelText.length, 6.2, 150, 260);
            var rightLabelBudget = estimateLabelWidth(longestOrgLabelLength + 6, 6.1, showPublisher ? 96 : 36, showPublisher ? 220 : 72);
            var minDiagramWidth = 420;
            var availableForMargins = Math.max(0, containerWidth - minDiagramWidth);
            var totalRequestedMargins = sourceLabelBudget + rightLabelBudget;
            var marginCompressionRatio = totalRequestedMargins > 0
                ? Math.min(1, availableForMargins / totalRequestedMargins)
                : 1;
            var margin = {
                top: 88,
                right: Math.max(showPublisher ? 96 : 32, Math.floor(rightLabelBudget * marginCompressionRatio)),
                bottom: 20,
                left: Math.max(120, Math.floor(sourceLabelBudget * marginCompressionRatio))
            };
            var width = Math.max(640, containerWidth - margin.left - margin.right);
            
            var displayedAttributeCount = nodes.filter(function(node) { return node.type === 'attribute'; }).length;
            var displayedTargetCount = nodes.filter(function(node) { return node.type === 'target'; }).length;
            var estimatedRows = Math.max(displayedAttributeCount, displayedTargetCount);
            var rowHeight = 22;
            var baseHeight = 110;
            var maxHeight = 1800;
            var height = Math.max(280, Math.min(maxHeight, baseHeight + (estimatedRows * rowHeight)));

            if (options.animateToggle) {
                $('#correlations-sankey').stop(true, true).animate({height: height + 'px', opacity: 0.18}, 180);
            } else {
                $('#correlations-sankey').css({height: height + 'px', opacity: 1});
            }
            
            height = height - margin.top - margin.bottom;

            $('#correlations-sankey').empty();
            var svg = d3.select("#correlations-sankey").append("svg")
                .attr("width", width + margin.left + margin.right)
                .attr("height", height + margin.top + margin.bottom)
                .style("opacity", options.animateToggle ? 0 : 1)
                .append("g")
                .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

            var sankey = d3.sankey()
                .nodeWidth(15)
                .nodePadding(10)
                .extent([[1, 1], [width - 1, height - 6]]);

            var graph = sankey({
                nodes: nodes.map(function(d) { return Object.assign({}, d); }),
                links: links.map(function(d) { return Object.assign({}, d); })
            });

            var sankeyNodeWidth = graph.nodes.length ? (graph.nodes[0].x1 - graph.nodes[0].x0) : 15;
            var attributeMaxX1 = 0;
            var targetNodes = [];
            var orgNodes = [];
            var targetDateExtents = { min: Infinity, max: -Infinity };
            var currentEventDateTs = _currentEventDateTs;
            graph.nodes.forEach(function(node) {
                if (node.type === 'attribute') {
                    attributeMaxX1 = Math.max(attributeMaxX1, node.x1);
                } else if (node.type === 'target') {
                    targetNodes.push(node);
                    var details = eventDetails && node.id ? eventDetails[node.id] : null;
                    var ts = details && details.date ? Date.parse(details.date + 'T00:00:00Z') : NaN;
                    if (isFinite(ts)) {
                        targetDateExtents.min = Math.min(targetDateExtents.min, ts);
                        targetDateExtents.max = Math.max(targetDateExtents.max, ts);
                        node.eventDateTs = ts;
                    }
                } else if (node.type === 'org') {
                    orgNodes.push(node);
                }
            });

            var hasSpreadableDates = isFinite(targetDateExtents.min)
                && isFinite(targetDateExtents.max)
                && targetDateExtents.max > targetDateExtents.min;
            var sankeyDomainMinTs = targetDateExtents.min;
            var sankeyDomainMaxTs = targetDateExtents.max;
            if (isFinite(currentEventDateTs)) {
                sankeyDomainMinTs = isFinite(sankeyDomainMinTs)
                    ? Math.min(sankeyDomainMinTs, currentEventDateTs)
                    : currentEventDateTs;
                sankeyDomainMaxTs = isFinite(sankeyDomainMaxTs)
                    ? Math.max(sankeyDomainMaxTs, currentEventDateTs)
                    : currentEventDateTs;
            }
            var useYearScale = isFinite(sankeyDomainMinTs)
                && isFinite(sankeyDomainMaxTs)
                && new Date(sankeyDomainMinTs).getUTCFullYear() !== new Date(sankeyDomainMaxTs).getUTCFullYear();
            var sankeyScaleMinTs = isFinite(sankeyDomainMinTs)
                ? (useYearScale ? startOfUtcYear(sankeyDomainMinTs) : startOfUtcMonth(sankeyDomainMinTs))
                : sankeyDomainMinTs;
            var sankeyScaleMaxTs = isFinite(sankeyDomainMaxTs)
                ? (useYearScale ? addUtcYears(startOfUtcYear(sankeyDomainMaxTs), 1) : addUtcMonths(startOfUtcMonth(sankeyDomainMaxTs), 1))
                : sankeyDomainMaxTs;
            var rightLabelPadding = showPublisher ? 16 : 10;
            var orgLabelReserve = showPublisher ? 260 : 28;
            var targetToOrgGap = alignToDate
                ? (showPublisher ? 84 : 52)
                : (showPublisher ? 56 : 36);
            var targetLaneStartFloor = attributeMaxX1 + 90;
            var targetLaneStart = targetLaneStartFloor;
            var timelineBandStartRatio = alignToDate ? 0.42 : 0.68;
            var timelineBandEndRatio = alignToDate ? 0.74 : 0.82;
            var preferredTimelineBandStart = Math.floor(width * timelineBandStartRatio);
            var preferredTimelineBandEnd = Math.floor(width * timelineBandEndRatio);
            var alignedLaneStart = Math.max(targetLaneStartFloor, preferredTimelineBandStart);
            var alignedLaneEnd = Math.max(alignedLaneStart + sankeyNodeWidth + 120, preferredTimelineBandEnd);
            var maxAlignedLaneEnd = width - orgLabelReserve - targetToOrgGap - sankeyNodeWidth;
            if (alignedLaneEnd > maxAlignedLaneEnd) {
                alignedLaneEnd = Math.max(alignedLaneStart + sankeyNodeWidth + 80, maxAlignedLaneEnd);
            }
            if (alignedLaneStart > alignedLaneEnd - sankeyNodeWidth - 80) {
                alignedLaneStart = Math.max(targetLaneStartFloor, alignedLaneEnd - sankeyNodeWidth - 80);
            }
            var orgColumnX0 = Math.max(attributeMaxX1 + targetToOrgGap + sankeyNodeWidth, width - sankeyNodeWidth - rightLabelPadding);
            var targetLaneEnd = alignToDate ? Math.min(alignedLaneEnd, orgColumnX0 - targetToOrgGap) : Math.max(alignedLaneEnd, orgColumnX0 - targetToOrgGap);
            var targetFixedX0 = Math.max(targetLaneStart, targetLaneEnd - Math.max(42, Math.floor(width * 0.035)));
            var orgLabelGap = 18;
            var targetLabelGap = 18;
            var targetHoverPad = 14;
            var orgLabelMaxLength = 34;

            function formatSankeyGridDate(ts, unit) {
                var d = new Date(ts);
                var y = d.getUTCFullYear();
                if (unit === 'year') {
                    return String(y);
                }
                var m = String(d.getUTCMonth() + 1).padStart(2, '0');
                return y + '-' + m;
            }

            function startOfUtcMonth(ts) {
                var d = new Date(ts);
                return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
            }

            function addUtcMonths(ts, count) {
                var d = new Date(ts);
                return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + count, 1);
            }

            function startOfUtcYear(ts) {
                var d = new Date(ts);
                return Date.UTC(d.getUTCFullYear(), 0, 1);
            }

            function addUtcYears(ts, count) {
                var d = new Date(ts);
                return Date.UTC(d.getUTCFullYear() + count, 0, 1);
            }

            function buildSankeyGridTicks(minTs, maxTs, laneStart, laneEnd) {
                var laneWidth = laneEnd - laneStart;
                if (!isFinite(minTs) || !isFinite(maxTs) || laneWidth <= 0) {
                    return [];
                }
                var tickUseYearScale = new Date(minTs).getUTCFullYear() !== new Date(maxTs).getUTCFullYear();
                var roundedMin = minTs;
                var roundedMax = maxTs;
                if (roundedMax <= roundedMin) {
                    return [{ x: laneStart + (laneWidth / 2), label: formatSankeyGridDate(roundedMin, tickUseYearScale ? 'year' : 'month'), isEdge: true }];
                }
                var ticks = [];
                var cursor = roundedMin;
                var index = 0;
                while (cursor <= roundedMax) {
                    var ratio = (cursor - roundedMin) / Math.max(1, (roundedMax - roundedMin));
                    ticks.push({
                        x: laneStart + (laneWidth * ratio),
                        label: formatSankeyGridDate(cursor, tickUseYearScale ? 'year' : 'month'),
                        isEdge: index === 0
                    });
                    cursor = tickUseYearScale ? addUtcYears(cursor, 1) : addUtcMonths(cursor, 1);
                    index++;
                }
                if (ticks.length) {
                    ticks[ticks.length - 1].isEdge = true;
                }
                var maxReadableTicks = tickUseYearScale ? 7 : 8;
                if (ticks.length > maxReadableTicks) {
                    var interval = Math.ceil((ticks.length - 1) / (maxReadableTicks - 1));
                    var limitedTicks = ticks.filter(function(tick, tickIndex) {
                        return tickIndex === 0 || tickIndex === ticks.length - 1 || (tickIndex % interval) === 0;
                    });
                    if (limitedTicks[limitedTicks.length - 1].x !== ticks[ticks.length - 1].x) {
                        limitedTicks.push(ticks[ticks.length - 1]);
                    }
                    ticks = limitedTicks;
                    ticks[0].isEdge = true;
                    ticks[ticks.length - 1].isEdge = true;
                }
                return ticks;
            }

            if (targetNodes.length > 0 && targetLaneEnd > targetLaneStart) {
                targetNodes.forEach(function(node) {
                    node.fixedX0 = targetFixedX0;
                    node.fixedX1 = node.fixedX0 + sankeyNodeWidth;
                    if (hasSpreadableDates && isFinite(node.eventDateTs)) {
                        var ratio = (node.eventDateTs - sankeyScaleMinTs) / Math.max(1, (sankeyScaleMaxTs - sankeyScaleMinTs));
                        ratio = Math.max(0, Math.min(1, ratio));
                        node.alignedX0 = Math.max(
                            alignedLaneStart,
                            Math.min(
                                alignedLaneEnd - sankeyNodeWidth,
                                alignedLaneStart + ((alignedLaneEnd - alignedLaneStart - sankeyNodeWidth) * ratio)
                            )
                        );
                    } else {
                        node.alignedX0 = alignedLaneStart + ((alignedLaneEnd - alignedLaneStart - sankeyNodeWidth) / 2);
                    }
                    node.x0 = alignToDate ? node.alignedX0 : node.fixedX0;
                    node.x1 = node.x0 + sankeyNodeWidth;
                });
            }

            if (orgNodes.length > 0) {
                orgNodes.forEach(function(node) {
                    node.x0 = orgColumnX0;
                    node.x1 = node.x0 + sankeyNodeWidth;
                });
            }

            function sankeyNodeFill(node) {
                if (node.type === 'target') {
                    return '#8fbfe8';
                }
                if (node.type === 'org') {
                    return '#b7c5d6';
                }
                if (node.type === 'source') {
                    return '#6fbe80';
                }
                if (node.type === 'attribute') {
                    return '#f39a1f';
                }
                return typeof color === 'function' ? color(node.type) : color;
            }

            function isSankeyInteractiveNode(node) {
                return node && (node.type === 'target' || node.type === 'attribute' || node.type === 'org');
            }

            function handleSankeyNodeClick(node) {
                if (node.type === 'target' && node.id) {
                    window.location.href = '<?php echo $baseurl; ?>/events/view/' + node.id;
                } else if (node.type === 'org' && node.id && node.id !== 'unknown') {
                    filterCorrelations(node.id, 'org');
                } else if (node.type === 'attribute' && node.id) {
                    filterCorrelations(node.id, 'attribute');
                }
            }

            function sankeyLinkConnectedToAttribute(link, node) {
                if (link.source && link.source.type === 'target' && link.target && link.target.type === 'org') {
                    return graph.links.some(function(candidateLink) {
                        return candidateLink.source === node && candidateLink.target === link.source;
                    });
                }
                return link.source === node || link.target === node;
            }

            function sankeyLinkConnectedToTarget(link, node) {
                if (node.type === 'target' && link.source === node && link.target && link.target.type === 'org') {
                    return true;
                }
                var isDirectLink = (link.target === node);
                if (isDirectLink) {
                    return true;
                }
                if (node.type === 'org') {
                    if (link.target === node && link.source && link.source.type === 'target') {
                        return true;
                    }
                    if (link.source && link.source.type === 'attribute' && link.target && link.target.type === 'target') {
                        var targetNode = link.target;
                        var connectedToOrg = false;
                        graph.links.forEach(function(candidateLink) {
                            if (candidateLink.source === targetNode && candidateLink.target === node) {
                                connectedToOrg = true;
                            }
                        });
                        return connectedToOrg;
                    }
                }
                var isPathFromSource = false;
                graph.links.forEach(function(candidateLink) {
                    if (candidateLink.target === node && candidateLink.source === link.target && link.source.type === 'source') {
                        isPathFromSource = true;
                    }
                });
                return isPathFromSource;
            }

            function sankeyNodeConnectedToAttribute(candidateNode, activeNode) {
                if (candidateNode === activeNode) {
                    return true;
                }
                if (candidateNode.type === 'source') {
                    return true;
                }
                if (candidateNode.type === 'org') {
                    return graph.links.some(function(link) {
                        return link.source === activeNode && link.target && link.target.type === 'target'
                            && graph.links.some(function(candidateLink) {
                                return candidateLink.source === link.target && candidateLink.target === candidateNode;
                            });
                    });
                }
                var connected = false;
                graph.links.forEach(function(link) {
                    if ((link.source === activeNode && link.target === candidateNode) || (link.target === activeNode && link.source === candidateNode)) {
                        connected = true;
                    }
                });
                return connected;
            }

            function sankeyNodeConnectedToTarget(candidateNode, activeNode) {
                if (candidateNode === activeNode) {
                    return true;
                }
                if (candidateNode.type === 'source') {
                    return true;
                }
                if (candidateNode.type === 'org') {
                    if (activeNode.type === 'org') {
                        return true;
                    }
                    if (activeNode.type === 'target') {
                        return graph.links.some(function(link) {
                            return link.source === activeNode && link.target === candidateNode;
                        });
                    }
                    if (activeNode.type === 'attribute') {
                        return graph.links.some(function(link) {
                            return link.source === activeNode && link.target && link.target.type === 'target'
                                && graph.links.some(function(candidateLink) {
                                    return candidateLink.source === link.target && candidateLink.target === candidateNode;
                                });
                        });
                    }
                    return false;
                }
                if (activeNode.type === 'target' && candidateNode.type === 'attribute') {
                    return graph.links.some(function(link) {
                        return link.source === candidateNode && link.target === activeNode;
                    });
                }
                if (activeNode.type === 'org') {
                    if (candidateNode.type === 'target') {
                        return graph.links.some(function(link) {
                            return link.source === candidateNode && link.target === activeNode;
                        });
                    }
                    if (candidateNode.type === 'attribute') {
                        return graph.links.some(function(link) {
                            return link.source === candidateNode && link.target && link.target.type === 'target'
                                && graph.links.some(function(candidateLink) {
                                    return candidateLink.source === link.target && candidateLink.target === activeNode;
                                });
                        });
                    }
                }
                var connected = false;
                graph.links.forEach(function(link) {
                    if ((link.target === activeNode && link.source === candidateNode) || (link.source === activeNode && link.target === candidateNode)) {
                        connected = true;
                    }
                });
                return connected;
            }

            function applySankeyHoverState(activeNode, linkOpacity) {
                if (!isSankeyInteractiveNode(activeNode)) {
                    return;
                }
                svg.selectAll('.sankey-link')
                    .transition()
                    .duration(200)
                    .style('stroke-opacity', function(link) {
                        var connected = activeNode.type === 'attribute'
                            ? sankeyLinkConnectedToAttribute(link, activeNode)
                            : sankeyLinkConnectedToTarget(link, activeNode);
                        if (!connected) {
                            return 0.08;
                        }
                        return linkOpacity;
                    });
                svg.selectAll('.sankey-label')
                    .transition()
                    .duration(200)
                    .style('opacity', function(node) {
                        var connected = activeNode.type === 'attribute'
                            ? sankeyNodeConnectedToAttribute(node, activeNode)
                            : sankeyNodeConnectedToTarget(node, activeNode);
                        return connected ? 1 : 0.1;
                    })
                    .style('fill', function(node) {
                        if (node.type === 'source') {
                            return '#21486f';
                        }
                        if (node.type === 'org') {
                            var connected = activeNode.type === 'attribute'
                                ? sankeyNodeConnectedToAttribute(node, activeNode)
                                : sankeyNodeConnectedToTarget(node, activeNode);
                            return connected ? '#31465b' : 'rgba(86, 105, 125, 0.5)';
                        }
                        return null;
                    })
                    .style('font-weight', function(node) {
                        if (node.type === 'org') {
                            var connected = activeNode.type === 'attribute'
                                ? sankeyNodeConnectedToAttribute(node, activeNode)
                                : sankeyNodeConnectedToTarget(node, activeNode);
                            return connected ? '700' : '400';
                        }
                        return isSankeyInteractiveNode(node) ? 'bold' : 'normal';
                    });
                svg.selectAll('.sankey-node rect:not(.sankey-target-hitbox)')
                    .transition()
                    .duration(200)
                    .style('opacity', function(node) {
                        if (!isSankeyInteractiveNode(node)) {
                            return 1;
                        }
                        var connected = activeNode.type === 'attribute'
                            ? sankeyNodeConnectedToAttribute(node, activeNode)
                            : sankeyNodeConnectedToTarget(node, activeNode);
                        if (node.type === 'org') {
                            return connected ? 0.9 : 0.22;
                        }
                        return connected ? 1 : 0.18;
                    });
            }

            function resetSankeyHoverState(activeNode) {
                if (!isSankeyInteractiveNode(activeNode)) {
                    return;
                }
                svg.selectAll('.sankey-link')
                    .transition()
                    .duration(200)
                    .style('stroke-opacity', function(link) {
                        return (link.source && link.source.type === 'target' && link.target && link.target.type === 'org') ? 0.24 : 0.5;
                    });
                svg.selectAll('.sankey-label')
                    .transition()
                    .duration(200)
                    .style('opacity', 1)
                    .style('fill', function(node) {
                        if (node.type === 'source') {
                            return '#21486f';
                        }
                        if (node.type === 'org') {
                            return 'rgba(86, 105, 125, 0.62)';
                        }
                        return null;
                    })
                    .style('font-weight', function(node) {
                        if (node.type === 'org') {
                            return '500';
                        }
                        return isSankeyInteractiveNode(node) ? 'bold' : 'normal';
                    });
                svg.selectAll('.sankey-node rect:not(.sankey-target-hitbox)')
                    .transition()
                    .duration(200)
                    .style('opacity', function(node) {
                        return node.type === 'org' ? 0.58 : 1;
                    });
            }

            // D3 v3 compatibility for scale and color
            var color = d3.scale ? d3.scale.category10() : (d3.scaleOrdinal ? d3.scaleOrdinal(d3.schemeCategory10) : function() { return '#428bca'; });

            var gridGroup = null;

            if (targetNodes.length > 0 && targetLaneEnd > targetLaneStart && alignToDate) {
                var gridTicks = buildSankeyGridTicks(sankeyScaleMinTs, sankeyScaleMaxTs, targetLaneStart, targetLaneEnd);
                var laneTop = Math.max(0, d3.min(targetNodes, function(d) { return d.y0; }) - 12);
                var laneBottom = Math.min(height, d3.max(targetNodes, function(d) { return d.y1; }) + 8);
                var laneHeight = Math.max(0, laneBottom - laneTop);

                if (laneHeight > 0) {
                    gridGroup = svg.append('g').attr('class', 'sankey-target-grid');
                    var timelineAxisY = laneTop - 28;
                    var timelineTickTopY = timelineAxisY - 12;

                    gridGroup.append('rect')
                        .attr('x', targetLaneStart)
                        .attr('y', laneTop)
                        .attr('width', targetLaneEnd - targetLaneStart)
                        .attr('height', laneHeight)
                        .attr('fill', 'rgba(84, 142, 94, 0.035)')
                        .attr('stroke', 'rgba(71, 109, 79, 0.12)')
                        .attr('stroke-width', 1);

                    gridGroup.append('line')
                        .attr('x1', targetLaneStart)
                        .attr('x2', targetLaneEnd)
                        .attr('y1', timelineAxisY)
                        .attr('y2', timelineAxisY)
                        .attr('stroke', 'rgba(63, 88, 70, 0.34)')
                        .attr('stroke-width', 2)
                        .attr('shape-rendering', 'geometricPrecision');

                    var tickGroup = gridGroup.selectAll('g')
                        .data(gridTicks)
                        .enter()
                        .append('g')
                        .attr('class', 'sankey-target-grid-tick');

                    tickGroup.append('line')
                        .attr('x1', function(d) { return d.x; })
                        .attr('x2', function(d) { return d.x; })
                        .attr('y1', timelineTickTopY)
                        .attr('y2', laneBottom)
                        .attr('stroke', function(d) { return d.isEdge ? 'rgba(63, 88, 70, 0.28)' : 'rgba(63, 88, 70, 0.18)'; })
                        .attr('stroke-width', 1)
                        .attr('shape-rendering', 'crispEdges');

                    var topLabelY = laneTop - 38;

                    tickGroup.append('line')
                        .attr('x1', function(d) { return d.x; })
                        .attr('x2', function(d) { return d.x; })
                        .attr('y1', timelineTickTopY)
                        .attr('y2', timelineAxisY)
                        .attr('stroke', 'rgba(63, 88, 70, 0.42)')
                        .attr('stroke-width', 1.4)
                        .attr('shape-rendering', 'crispEdges');

                    var tickLabel = tickGroup.append('text')
                        .attr('x', function(d) { return d.x; })
                        .attr('y', topLabelY)
                        .attr('text-anchor', 'start')
                        .attr('dx', '3px')
                        .attr('dy', '-2px')
                        .attr('transform', function(d) {
                            return 'rotate(-55,' + d.x + ',' + topLabelY + ')';
                        })
                        .style('font', '700 10px sans-serif')
                        .style('fill', '#44515f')
                        .text(function(d) { return d.label; });

                    if (isFinite(currentEventDateTs) && isFinite(sankeyScaleMinTs) && isFinite(sankeyScaleMaxTs) && sankeyScaleMaxTs > sankeyScaleMinTs) {
                        var currentEventRatio = (currentEventDateTs - sankeyScaleMinTs) / Math.max(1, (sankeyScaleMaxTs - sankeyScaleMinTs));
                        currentEventRatio = Math.max(0, Math.min(1, currentEventRatio));
                        var currentEventX = targetLaneStart + ((targetLaneEnd - targetLaneStart) * currentEventRatio);
                        var currentEventBlockText = truncateSourceLabel(currentEventName);
                        var currentEventNodeY = laneTop - 18;
                        var currentEventNodeHeight = 16;
                        var currentEventNodeWidth = sankeyNodeWidth;
                        var currentEventNodeX = Math.max(targetLaneStart, Math.min(targetLaneEnd - currentEventNodeWidth, currentEventX - (currentEventNodeWidth / 2)));
                        var currentEventNodeCenterY = currentEventNodeY + (currentEventNodeHeight / 2);
                        var currentEventLineTopY = currentEventNodeCenterY;
                        var currentEventLabelX = currentEventNodeX + currentEventNodeWidth + targetLabelGap;
                        var currentEventLabelY = currentEventNodeCenterY;
                        var currentEventLeaderEndX = currentEventLabelX - 6;
                        var currentEventMarkerGroup = gridGroup.append('g').attr('class', 'sankey-current-event-marker');

                        currentEventMarkerGroup.append('rect')
                            .attr('x', currentEventNodeX)
                            .attr('y', currentEventNodeY)
                            .attr('width', currentEventNodeWidth)
                            .attr('height', currentEventNodeHeight)
                            .attr('fill', '#6fbe80')
                            .append('title')
                            .text(currentEventFullTitle);

                        currentEventMarkerGroup.append('text')
                            .attr('x', currentEventNodeX + (currentEventNodeWidth / 2))
                            .attr('y', currentEventNodeCenterY)
                            .attr('text-anchor', 'middle')
                            .attr('dy', '0.35em')
                            .style('font', '700 10px sans-serif')
                            .style('fill', '#ffffff')
                            .text('★')
                            .append('title')
                            .text(currentEventFullTitle);

                        currentEventMarkerGroup.append('line')
                            .attr('x1', currentEventNodeX + currentEventNodeWidth)
                            .attr('x2', currentEventLeaderEndX)
                            .attr('y1', currentEventNodeCenterY)
                            .attr('y2', currentEventNodeCenterY)
                            .attr('stroke', 'rgba(74, 92, 112, 0.45)')
                            .attr('stroke-width', 1)
                            .attr('shape-rendering', 'crispEdges')
                            .attr('pointer-events', 'none');

                        currentEventMarkerGroup.append('text')
                            .attr('x', currentEventLabelX)
                            .attr('y', currentEventLabelY)
                            .attr('text-anchor', 'start')
                            .attr('dy', '0.35em')
                            .style('font', '700 10px sans-serif')
                            .style('fill', '#26313d')
                            .text(currentEventBlockText)
                            .append('title')
                            .text(currentEventFullTitle);
                    }

                }
            }

            // D3 v3 compatibility: use enter().append() instead of join()
            var nodeGroup = svg.append("g")
                .selectAll("g")
                .data(graph.nodes)
                .enter()
                .append("g")
                .attr("class", function(d) { return 'sankey-node sankey-node-' + d.type; });

            nodeGroup.filter(function(d) { return d.type === 'target' || d.type === 'org'; })
                .append('rect')
                .attr('class', function(d) { return d.type === 'org' ? 'sankey-org-hitbox' : 'sankey-target-hitbox'; })
                .attr('x', function(d) { return d.type === 'org' ? d.x0 - 2 : Math.max(targetLaneStart - 4, d.x0 - targetHoverPad); })
                .attr('y', function(d) { return Math.max(0, d.y0 - 3); })
                .attr('width', function(d) {
                    if (d.type === 'org') {
                        var orgLabel = d.name || '';
                        var visibleOrgLabel = orgLabel.length > orgLabelMaxLength ? orgLabel.substring(0, orgLabelMaxLength - 3) + '...' : orgLabel;
                        return Math.max((d.x1 - d.x0) + orgLabelGap + (visibleOrgLabel.length * 6.2) + 8, 52);
                    }
                    return Math.max((d.x1 - d.x0) + targetHoverPad + targetLabelGap + 8, 42);
                })
                .attr('height', function(d) { return Math.max((d.y1 - d.y0) + 6, 16); })
                .attr('fill', 'rgba(255,255,255,0)')
                .attr('cursor', 'pointer')
                .on("click", handleSankeyNodeClick)
                .on("mouseover", function(d) { applySankeyHoverState(d, 0.7); })
                .on("mouseout", resetSankeyHoverState);

            nodeGroup.append("rect")
                .attr("x", function(d) { return d.x0; })
                .attr("y", function(d) { return d.y0; })
                .attr("height", function(d) { return d.y1 - d.y0; })
                .attr("width", function(d) { return d.x1 - d.x0; })
                .attr("fill", sankeyNodeFill)
                .attr("cursor", function(d) { return isSankeyInteractiveNode(d) ? 'pointer' : 'default'; })
                .on("click", handleSankeyNodeClick)
                .on("mouseover", function(d) { applySankeyHoverState(d, 0.7); })
                .on("mouseout", resetSankeyHoverState)
                .style('opacity', function(d) { return d.type === 'org' ? 0.42 : 1; })
                .append("title")
                .text(function(d) { return d.fullTitle || d.name; });

            var link = svg.append("g")
                .attr("fill", "none")
                .attr("stroke-opacity", 0.5)
                .selectAll("path")
                .data(graph.links)
                .enter()
                .append("path")
                .attr("class", "sankey-link")
                .attr("d", function(d) {
                    var x0 = d.source.x1,
                        x1 = d.target.x0,
                        xi = d3.interpolateNumber(x0, x1),
                        x2 = xi(0.5),
                        x3 = xi(0.5),
                        y0 = d.y0,
                        y1 = d.y1;
                    return "M" + x0 + "," + y0
                         + "C" + x2 + "," + y0
                         + " " + x3 + "," + y1
                         + " " + x1 + "," + y1;
                })
                .attr("stroke", function(d) {
                    if (d.source && d.source.type === 'source' && d.target && d.target.type === 'attribute') {
                        return '#f6e8a6';
                    }
                    if (d.source && d.source.type === 'attribute' && d.target && d.target.type === 'target') {
                        return '#7ec8f3';
                    }
                    if (d.source && d.source.type === 'target' && d.target && d.target.type === 'org') {
                        return 'rgba(116, 147, 179, 0.22)';
                    }
                    return typeof color === 'function' ? color(d.source.type) : color;
                })
                .attr("stroke-width", function(d) { return Math.max(1, d.width); });

            var leaderLines = svg.append('g')
                .selectAll('line')
                .data(graph.nodes.filter(function(d) { return d.type === 'target'; }))
                .enter()
                .append('line')
                .attr('class', 'sankey-target-label-line')
                .attr('x1', function(d) { return d.x1; })
                .attr('x2', function(d) { return d.x1 + targetLabelGap - 6; })
                .attr('y1', function(d) { return (d.y0 + d.y1) / 2; })
                .attr('y2', function(d) { return (d.y0 + d.y1) / 2; })
                .attr('stroke', 'rgba(74, 92, 112, 0.45)')
                .attr('stroke-width', 1)
                .attr('shape-rendering', 'crispEdges')
                .attr('pointer-events', 'none');

            var labelSelection = svg.append("g")
                .style("font", "10px sans-serif")
                .selectAll("text")
                .data(graph.nodes)
                .enter()
                .append("text")
                .attr("class", "sankey-label")
                .attr("x", function(d) {
                    if (d.type === 'source') {
                        return d.x0 - 18;
                    }
                    if (d.type === 'attribute') {
                        return d.x0 - 8;
                    }
                    if (d.type === 'target') {
                        return d.x1 + targetLabelGap;
                    }
                    if (d.type === 'org') {
                        return d.x1 + orgLabelGap;
                    }
                    return d.x0 < width / 2 ? d.x1 + 6 : d.x0 - 6;
                })
                .attr("y", function(d) { return (d.y1 + d.y0) / 2; })
                .attr("dy", "0.35em")
                .attr("text-anchor", function(d) {
                    if (d.type === 'source') {
                        return 'end';
                    }
                    if (d.type === 'attribute') {
                        return 'end';
                    }
                    if (d.type === 'target') {
                        return 'start';
                    }
                    if (d.type === 'org') {
                        return 'start';
                    }
                    return d.x0 < width / 2 ? 'start' : 'end';
                })
                .attr("cursor", function(d) { return isSankeyInteractiveNode(d) ? 'pointer' : 'default'; })
                .style("fill", function(d) {
                    if (d.type === 'source') {
                        return '#21486f';
                    }
                    if (d.type === 'org') {
                        return 'rgba(86, 105, 125, 0.48)';
                    }
                    return null;
                })
                .style("paint-order", function(d) { return d.type === 'source' ? 'stroke' : null; })
                .style("stroke", function(d) { return d.type === 'source' ? 'rgba(255, 255, 255, 0.96)' : 'none'; })
                .style("stroke-width", function(d) { return d.type === 'source' ? 4 : 0; })
                .style("stroke-linejoin", function(d) { return d.type === 'source' ? 'round' : null; })
                .style("font-weight", function(d) {
                    if (d.type === 'org') {
                        return '400';
                    }
                    return isSankeyInteractiveNode(d) ? 'bold' : 'normal';
                });

            labelSelection.append("title")
                .text(function(d) { return d.fullTitle || d.name; });

            labelSelection
                .on("click", handleSankeyNodeClick)
                .on("mouseover", function(d) { applySankeyHoverState(d, 0.5); })
                .on("mouseout", resetSankeyHoverState)
                .text(function(d) {
                    if (d.type === 'source') {
                        return '★ ' + truncateSourceLabel(d.name);
                    }
                    var maxLength = d.type === 'target' ? 60 : (d.type === 'org' ? orgLabelMaxLength : (d.x0 < width / 2 ? 50 : 70));
                    var label = d.name.length > maxLength ? d.name.substring(0, maxLength - 3) + '...' : d.name;
                    return label;
                });

            svg.append('g')
                .attr('class', 'sankey-target-label-hitboxes')
                .selectAll('rect')
                .data(graph.nodes.filter(function(d) { return d.type === 'target'; }))
                .enter()
                .append('rect')
                .attr('x', function(d) { return d.x1 + targetLabelGap - 4; })
                .attr('y', function(d) { return Math.max(0, ((d.y0 + d.y1) / 2) - 8); })
                .attr('width', function(d) {
                    var label = d.name || '';
                    var maxLength = 60;
                    var visibleLabel = label.length > maxLength ? label.substring(0, maxLength - 3) + '...' : label;
                    return Math.max(42, (visibleLabel.length * 6.2) + 8);
                })
                .attr('height', 16)
                .attr('fill', 'rgba(255,255,255,0)')
                .attr('cursor', 'pointer')
                .on("click", handleSankeyNodeClick)
                .on("mouseover", function(d) { applySankeyHoverState(d, 0.5); })
                .on("mouseout", resetSankeyHoverState)
                .append("title")
                .text(function(d) { return d.fullTitle || d.name; });

            function updateTargetNodePositions(animate) {
                var duration = animate ? 450 : 0;
                var activeAlignToDate = $('#sankey-date-align-toggle').is(':checked');

                graph.nodes.forEach(function(node) {
                    if (node.type !== 'target') {
                        return;
                    }
                    node.x0 = activeAlignToDate ? node.alignedX0 : node.fixedX0;
                    node.x1 = node.x0 + sankeyNodeWidth;
                });

                nodeGroup.filter(function(d) { return d.type === 'target'; })
                    .selectAll('rect:not(.sankey-target-hitbox)')
                    .transition()
                    .duration(duration)
                    .attr('x', function(d) { return d.x0; })
                    .attr('width', function(d) { return d.x1 - d.x0; });

                nodeGroup.filter(function(d) { return d.type === 'target'; })
                    .select('.sankey-target-hitbox')
                    .transition()
                    .duration(duration)
                    .attr('x', function(d) { return Math.max(targetLaneStart - 4, d.x0 - targetHoverPad); })
                    .attr('width', function(d) { return Math.max((d.x1 - d.x0) + targetHoverPad + targetLabelGap + 8, 42); });

                link.transition()
                    .duration(duration)
                    .attr("d", function(d) {
                        var x0 = d.source.x1,
                            x1 = d.target.x0,
                            xi = d3.interpolateNumber(x0, x1),
                            x2 = xi(0.5),
                            x3 = xi(0.5),
                            y0 = d.y0,
                            y1 = d.y1;
                        return "M" + x0 + "," + y0
                             + "C" + x2 + "," + y0
                             + " " + x3 + "," + y1
                             + " " + x1 + "," + y1;
                    });

                leaderLines.transition()
                    .duration(duration)
                    .attr('x1', function(d) { return d.x1; })
                    .attr('x2', function(d) { return d.x1 + targetLabelGap - 6; });

                labelSelection.filter(function(d) { return d.type === 'target'; })
                    .transition()
                    .duration(duration)
                    .attr('x', function(d) { return d.x1 + targetLabelGap; });

                if (gridGroup) {
                    gridGroup.transition()
                        .duration(duration)
                        .style('opacity', activeAlignToDate ? 1 : 0);
                }

            }

            $('#sankey-date-align-toggle').off('change.sankeyAlign').on('change.sankeyAlign', function() {
                updateTargetNodePositions(true);
            });

            $('#sankey-latest-events-toggle').off('change.sankeyLatest').on('change.sankeyLatest', function() {
                renderSankey(data, eventDetails, filterAttributeId, {animateToggle: true});
            });

            $('#sankey-show-publisher-toggle').off('change.sankeyPublisher').on('change.sankeyPublisher', function() {
                renderSankey(data, eventDetails, filterAttributeId, {animateToggle: true});
            });

            if (options.animateToggle) {
                $('#correlations-sankey').stop(true, true).animate({opacity: 1}, 260);
                d3.select('#correlations-sankey svg').transition().duration(260).style('opacity', 1);
            }
        }

    $(document).ready(function() {
        $(document).off('click.correlationCommentChip').on('click.correlationCommentChip', '.beta-correlation-filter-comment-chip', function() {
            scrollToCorrelationCommentTarget($(this).data('event-id'), String($(this).data('current-event')) === '1');
        });

        $('#correlations-timeline-view-toggle').off('change.timelineView').on('change.timelineView', function() {
            updateCorrelationsTimelineVisibility();
        });

        function updatePublishedLabelState(isPublished) {
            var $label = $('#publishedLabel');
            if (!$label.length) {
                return;
            }
            $label.removeClass('state-published state-unpublished')
                .addClass(isPublished ? 'state-published' : 'state-unpublished')
                .text(isPublished ? '<?php echo addslashes(__('Published')); ?>' : '<?php echo addslashes(__('Unpublished')); ?>');
        }

        $('a[data-toggle="tab"][href="#correlations"]').on('shown.bs.tab', function (e) {
            loadCorrelations();
        });

        <?php if (!empty($firstEventReportId)): ?>
        $('#summary-report-iframe').on('load', function() {
            refreshReportPreviewHeight();
        });

        $('a[data-toggle="tab"][href="#summary"]').on('shown.bs.tab', function () {
            refreshReportPreviewHeight();
        });

        if (window.location.hash === '#summary' || !window.location.hash || window.location.hash === '#attributes') {
            refreshReportPreviewHeight();
        }
        <?php endif; ?>

        // Check if we are already on the correlations tab on page load
        if (window.location.hash === '#correlations') {
            loadCorrelations();
        }

        if ($('#publishedToggle').length) {
            updatePublishedLabelState($('#publishedToggle').is(':checked'));
        }

        $('#publishedToggle').change(function() {
            var $toggle = $(this);
            var id = $toggle.data('id');
            var isChecked = $toggle.is(':checked');
            var action = isChecked ? 'publish' : 'unpublish';
            var url = '<?php echo $baseurl; ?>/events/' + action + '/' + id + '.json';
            
            // Disable to prevent double clicks
            $toggle.prop('disabled', true);

            $.ajax({
                url: url,
                type: 'POST',
                dataType: 'json',
                success: function(response) {
                    $toggle.prop('disabled', false);
                    if (response.saved || (response.response && response.response.saved)) {
                         updatePublishedLabelState(isChecked);
                         showMessage('success', response.message || (response.response ? response.response.message : 'Event updated'));
                    } else {
                        // Revert
                        $toggle.prop('checked', !isChecked);
                        updatePublishedLabelState(!isChecked);
                        showMessage('fail', response.message || (response.response ? response.response.message : 'Action failed'));
                        if (response.errors) {
                             console.error(response.errors);
                        }
                    }
                },
                error: function(xhr) {
                    $toggle.prop('disabled', false);
                    $toggle.prop('checked', !isChecked);
                    updatePublishedLabelState(!isChecked);
                    xhrFailCallback(xhr);
                }
            });
        });
    });

    window.viewFullReport = function(reportId) {
        var url = baseurl + '/eventReports/viewRendered/' + reportId;
        var modalHtml = 
            '<div id="reportViewModal" class="modal hide fade" tabindex="-1" role="dialog" style="width: 94%; left: 3%; margin-left: 0; top: 3%; height: 94%;">' +
            '    <div class="modal-header" style="padding: 10px 15px;">' +
            '        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">×</button>' +
            '        <h3 style="margin: 0; line-height: 1.5;"><?php echo __('Report Preview'); ?></h3>' +
            '    </div>' +
            '    <div class="modal-body" style="max-height: none; height: calc(100% - 100px); padding: 0; overflow: hidden;">' +
            '        <iframe src="' + url + '" style="width: 100%; height: 100%; border: none;"></iframe>' +
            '    </div>' +
            '    <div class="modal-footer" style="padding: 10px 15px;">' +
            '        <button class="btn btn-primary" data-dismiss="modal" aria-hidden="true"><?php echo __('Close'); ?></button>' +
            '    </div>' +
            '</div>';
        
        $('#reportViewModal').remove();
        $('body').append(modalHtml);
        $('#reportViewModal').modal();
    };
    // Pending filter to apply once correlations are loaded
    var _pendingCorrelationFilter = null;
    var _activeCorrelationFilter = null;
    var _activeCorrelationFilterType = null;
    var _correlationAttributeMap = null;

    function buildFilteredCorrelationEventDetails(attributeId) {
        if (!_correlationEventDetails) {
            return {};
        }
        if (!attributeId || !_correlationData || !_correlationData[attributeId]) {
            return _correlationEventDetails;
        }

        var filteredDetails = {};
        _correlationData[attributeId].forEach(function(rel) {
            if (!rel || !rel.id || !_correlationEventDetails[rel.id]) {
                return;
            }
            filteredDetails[rel.id] = _correlationEventDetails[rel.id];
        });
        return filteredDetails;
    }

    function buildFilteredCorrelationEventDetailsByOrg(orgId) {
        if (!_correlationEventDetails || !orgId) {
            return _correlationEventDetails || {};
        }

        var filteredDetails = {};
        Object.keys(_correlationEventDetails).forEach(function(eid) {
            var details = _correlationEventDetails[eid];
            if (details && String(details.org) === String(orgId)) {
                filteredDetails[eid] = details;
            }
        });
        return filteredDetails;
    }

    function collectFilteredCorrelationComments(filterValue, filterType) {
        if (!_correlationAttributeMap || !filterValue) {
            return [];
        }

        var seen = {};
        var comments = [];
        var registerComment = function(comment, eventId, title, isCurrentEvent) {
            var normalizedComment = comment ? String(comment).trim() : '';
            if (!normalizedComment || seen[normalizedComment]) {
                return;
            }
            seen[normalizedComment] = true;
            comments.push({
                comment: normalizedComment,
                eventId: eventId ? String(eventId) : '',
                title: title || normalizedComment,
                isCurrentEvent: !!isCurrentEvent
            });
        };

        if (filterType === 'attribute') {
            var $currentRow = $('[data-primary-id="' + String(filterValue).replace(/"/g, '\\"') + '"]').first();
            var currentComment = $currentRow.find('.beta-attr-comment-inline span').first().text().trim();
            if (currentComment) {
                registerComment(currentComment, '<?php echo h($event['Event']['id']); ?>', '<?php echo addslashes(h($event['Event']['info'])); ?>', true);
            }
            Object.keys(_correlationAttributeMap).forEach(function(eventId) {
                (_correlationAttributeMap[eventId] || []).forEach(function(entry) {
                    if (String(entry.id) !== String(filterValue)) {
                        return;
                    }
                    var attr = entry && entry.attribute ? entry.attribute : null;
                    registerComment(
                        attr && attr.comment ? String(attr.comment).trim() : '',
                        eventId,
                        (_correlationEventDetails && _correlationEventDetails[eventId] && _correlationEventDetails[eventId].info) ? _correlationEventDetails[eventId].info : '',
                        false
                    );
                });
            });
        } else {
            Object.keys(_correlationAttributeMap).forEach(function(eventId) {
                if (!_correlationEventDetails || !_correlationEventDetails[eventId] || String(_correlationEventDetails[eventId].org) !== String(filterValue)) {
                    return;
                }
                (_correlationAttributeMap[eventId] || []).forEach(function(entry) {
                    var attr = entry && entry.attribute ? entry.attribute : null;
                    registerComment(
                        attr && attr.comment ? String(attr.comment).trim() : '',
                        eventId,
                        _correlationEventDetails[eventId].info || '',
                        false
                    );
                });
            });
        }

        comments.sort(function(a, b) {
            return a.comment.localeCompare(b.comment);
        });

        return comments;
    }

    function renderFilteredCorrelationComments(filterValue, filterType) {
        var $comments = $('#correlations-filter-comments');
        if (!$comments.length) {
            return;
        }

        if (!filterValue || !filterType) {
            $comments.empty().hide();
            return;
        }

        var comments = collectFilteredCorrelationComments(filterValue, filterType);
        if (!comments.length) {
            $comments.empty().hide();
            return;
        }

        var html = '<div class="beta-correlation-filter-comments-label"><?php echo addslashes(__('Cross-event comments:')); ?></div>';
        comments.forEach(function(commentEntry) {
            html += buildFilteredCorrelationCommentChip(commentEntry);
        });

        $comments.html(html).show();
    }

    function updateCorrelationsTimelineVisibility() {
        var timeline = document.getElementById('correlationsEventTimeline');
        if (!timeline) return;
        var showTimeline = $('#correlations-timeline-view-toggle').is(':checked');
        timeline.style.display = showTimeline ? '' : 'none';
    }

    function filterCorrelations(filterValue, filterType) {
        filterType = filterType || 'attribute';
        // Always switch to correlations tab
        $('.nav-tabs a[href="#correlations"]').tab('show');

        // If correlations haven't loaded yet, store the filter and apply it once loaded
        if (!_correlationData) {
            _pendingCorrelationFilter = {
                value: filterValue,
                type: filterType
            };
            return;
        }

        _applyCorrelationFilter(filterValue, filterType);

        // Scroll to top of correlations tab
        $('html, body').animate({
            scrollTop: $(".beta-tabs-container").offset().top
        }, 500);
    }

    function animateCorrelationFilterTransition(applyFilterFn) {
        var $sankey = $('#correlations-sankey');

        if (!$sankey.length) {
            applyFilterFn();
            return;
        }

        $sankey.stop(true, true).animate({opacity: 0.18}, 140, function() {
            applyFilterFn();
            $('#correlations-sankey').stop(true, true).css('opacity', 0.18).animate({opacity: 1}, 240);
        });
    }

    function _applyCorrelationFilter(filterValue, filterType) {
        filterType = filterType || 'attribute';
        _activeCorrelationFilter = filterValue || null;
        _activeCorrelationFilterType = filterValue ? filterType : null;

        function buildThisEventMetaBlock(metaBlockHtml, attrCategory, attrType, attrValue) {
            if (metaBlockHtml) {
                return '          <td colspan="2">' + metaBlockHtml + '</td>';
            }

            var html = '';
            html += '          <td colspan="2">';
            html += '            <div class="beta-correlation-meta">';
            if (attrCategory || attrType) {
                html += '              <div class="beta-attr-type-path">';
                html += '                <span class="beta-correlation-chevrons">';
                if (attrCategory) {
                    html += '                  <span class="beta-correlation-chevron beta-correlation-category"><span>' + escapeHtml(attrCategory) + '</span></span>';
                }
                if (attrType) {
                    html += '                  <span class="beta-correlation-chevron beta-correlation-type"><span>' + escapeHtml(attrType) + '</span></span>';
                }
                html += '                </span>';
                html += '              </div>';
            }
            html += '              <div class="beta-correlation-value-row">';
            html += '                <span class="beta-correlation-value-link">' + escapeHtml(attrValue) + '</span>';
            html += '              </div>';
            html += '            </div>';
            html += '          </td>';
            return html;
        }

        function buildThisEventCorrelationCard(currentEventDateSafe, currentEventOrg, currentEventId, currentEventInfo, metaBlockHtml, attrCategory, attrType, attrValue, idsHtml, correlationHtml, sightingsHtml, distributionHtml, dateHtml) {
            var html = '';
            html += '<div id="correlations-this-event-card" class="beta-card correlation-event-card" style="border-left-color: #5cb85c;">';
            html += '  <div class="beta-card-header" style="display: flex; justify-content: space-between; align-items: center; gap: 16px;">';
            html += '    <div style="display: flex; align-items: center; gap: 10px;">';
            if (currentEventDateSafe) {
                html += '      <span class="label label-default" style="font-weight: normal;">' + currentEventDateSafe + '</span>';
            }
            if (currentEventOrg) {
                html += '      <span class="beta-correlation-org"><i class="fa fa-building"></i>' + currentEventOrg + '</span>';
            }
            html += '      <a class="beta-correlation-event-link" href="<?php echo $baseurl; ?>/events/view/' + currentEventId + '">#' + currentEventId + ' ' + currentEventInfo + '</a>';
            html += '      <span class="label label-success" style="font-size: 12px; padding: 4px 8px;"><i class="fa fa-star"></i> <?php echo __('This Event'); ?></span>';
            html += '    </div>';
            html += '    <span style="font-size: 11px; color: #3d8b5e; font-style: italic;"><?php echo __('Source attribute'); ?></span>';
            html += '  </div>';
            html += '  <div class="beta-card-body" style="padding: 0;">';
            html += '    <table class="beta-attr-table" style="margin-top: 0;">';
            html += '      <tbody>';
            html += '        <tr class="beta-correlation-row">';
            html += '          <td class="beta-correlation-anchor-cell"><i class="fa fa-star" style="color: #5cb85c;"></i></td>';
            html += buildThisEventMetaBlock(metaBlockHtml, attrCategory, attrType, attrValue);
            html += '          <td class="col-related"></td>';
            html += '          <td style="text-align: center;">' + idsHtml + '</td>';
            html += '          <td class="col-correlation" style="text-align: center;">' + correlationHtml + '</td>';
            html += '          <td class="col-sightings" style="text-align: center;">' + sightingsHtml + '</td>';
            html += '          <td class="col-distribution beta-correlation-distribution-cell">' + distributionHtml + '</td>';
            html += '          <td class="col-date beta-correlation-date-cell" style="width: 90px;">' + dateHtml + '</td>';
            html += '        </tr>';
            html += '      </tbody>';
            html += '    </table>';
            html += '  </div>';
            html += '</div>';
            return html;
        }

        // Re-render the Sankey with or without filter
        animateCorrelationFilterTransition(function() {
            if (_correlationData && _correlationEventDetails) {
                if (filterValue) {
                    var filterLabel = filterValue;
                    if (filterType === 'attribute' && _correlationData[filterValue] && _correlationData[filterValue].length > 0) {
                        filterLabel = _correlationData[filterValue][0].value || filterValue;
                    } else if (filterType === 'org') {
                        var matchingOrgDetails = Object.keys(_correlationEventDetails).map(function(eid) {
                            return _correlationEventDetails[eid];
                        }).find(function(details) {
                            return details && String(details.org) === String(filterValue);
                        });
                        filterLabel = matchingOrgDetails && matchingOrgDetails.orgName ? matchingOrgDetails.orgName : filterValue;
                    }
                    renderCorrelationsTimeline(filterType === 'attribute' ? buildFilteredCorrelationEventDetails(filterValue) : buildFilteredCorrelationEventDetailsByOrg(filterValue));
                    renderSankey(_correlationData, _correlationEventDetails, filterType === 'attribute' ? filterValue : null, {animateToggle: true, filterOrgId: filterType === 'org' ? filterValue : null});
                    $('#sankey-filter-label').text('<?php echo __('Filtered'); ?>: ' + filterLabel);
                    $('#sankey-filter-badge').show();
                } else {
                    renderCorrelationsTimeline(_correlationEventDetails);
                    renderSankey(_correlationData, _correlationEventDetails, null, {animateToggle: true});
                    $('#sankey-filter-badge').hide();
                    $('#sankey-filter-label').text('');
                }
            }

            // Remove any existing "this event" card
            $('#correlations-this-event-card').remove();

            // Filter the correlations table cards and rows within them
            var cards = $('.correlation-event-card');
            if (filterValue) {
                var attrValue = filterValue;
                var attrType = '';
                var attrCategory = '';
                if (filterType === 'attribute' && _correlationData && _correlationData[filterValue] && _correlationData[filterValue].length > 0) {
                    var firstRel = _correlationData[filterValue][0];
                    attrValue = firstRel.value || filterValue;
                } else if (filterType === 'org') {
                    var matchingOrgCard = $('.correlation-event-card[data-org-id="' + String(filterValue).replace(/"/g, '\\"') + '"]').first();
                    var matchingOrgName = matchingOrgCard.data('org-name');
                    if (matchingOrgName) {
                        attrValue = matchingOrgName;
                    }
                }
                // Try to get type/category from the DOM (attributes table)
                var domRow = filterType === 'attribute' ? $('[data-primary-id="' + filterValue + '"]') : $();
                if (filterType === 'attribute' && domRow.length) {
                    attrType = domRow.find('.beta-type-insight').first().text().trim();
                    attrCategory = domRow.find('.beta-category-label').first().text().trim();
                }

                // Show only matching cards; for attribute filters also narrow to matching rows
                cards.each(function() {
                    var card = $(this);
                    var isMatch = false;
                    if (filterType === 'attribute') {
                        var attrIds = card.data('attribute-ids') || '';
                        isMatch = attrIds.indexOf(',' + filterValue + ',') !== -1;
                    } else if (filterType === 'org') {
                        isMatch = String(card.data('org-id') || '') === String(filterValue);
                    }
                    if (isMatch) {
                        card.show();
                        card.find('.beta-correlation-row').each(function() {
                            var row = $(this);
                            if (filterType === 'attribute') {
                                var rowAttrId = row.data('attribute-id');
                                row.toggle(rowAttrId == filterValue);
                            } else {
                                row.show();
                            }
                        });
                    } else {
                        card.hide();
                    }
                });

                // Build "This Event" card only for attribute filters
                var currentEventId = '<?php echo h($event['Event']['id']); ?>';
                var currentEventInfo = '<?php echo addslashes(h($event['Event']['info'])); ?>';
                var currentEventDate = '<?php echo addslashes(h($event['Event']['date'])); ?>';
                var currentEventOrgName = '<?php echo addslashes(h(isset($event['Orgc']['name']) ? $event['Orgc']['name'] : '')); ?>';
                var currentEventOrg = currentEventOrgName ? $('<div/>').text(currentEventOrgName).html() : '';
                var currentEventDateSafe = currentEventDate ? $('<div/>').text(currentEventDate).html() : '';

                // Clone cells from the DOM row for a complete display
                var metaBlockHtml = '';
                var idsHtml = '';
                var correlationHtml = '';
                var sightingsHtml = '';
                var distributionHtml = '';
                var dateHtml = '';

                if (filterType === 'attribute' && domRow.length) {
                    // Clone the full meta block (includes type path, value, tags, galaxies)
                    var metaBlock = domRow.find('.beta-attr-meta-block').first().clone();
                    metaBlock.find('.beta-tagging-links').remove();
                    metaBlock.find('.beta-row-menu').remove();
                    // Make the attr-value non-clickable
                    metaBlock.find('.attr-value-correlatable').removeClass('attr-value-correlatable').removeAttr('onclick').css({'cursor': 'default', 'border-bottom': 'none'});
                    metaBlock.find('.beta-correlation-inline-indicator, .beta-correlation-branch-link').remove();
                    metaBlockHtml = metaBlock.prop('outerHTML');

                    // IDS toggle cell (the shield icon)
                    var idsCell = domRow.find('td:has(.beta-ids-toggle)').first();
                    if (idsCell.length) {
                        var idsClone = idsCell.clone();
                        idsClone.find('.beta-ids-toggle').removeAttr('onclick').css('cursor', 'default');
                        idsHtml = idsClone.html();
                    }
                    // Correlation toggle cell
                    var corrCell = domRow.find('.col-correlation').first();
                    if (corrCell.length) {
                        var corrClone = corrCell.clone();
                        corrClone.find('.beta-correlation-toggle').removeAttr('onclick').css('cursor', 'default');
                        correlationHtml = corrClone.html();
                    }
                    // Sightings cell
                    var sightCell = domRow.find('.col-sightings').first();
                    if (sightCell.length) {
                        sightingsHtml = sightCell.clone().html();
                    }
                    // Distribution cell
                    var distCell = domRow.find('.col-distribution').first();
                    if (distCell.length) {
                        distributionHtml = distCell.clone().html();
                    }
                    // Date cell
                    var dateCell = domRow.find('.col-date').first();
                    if (dateCell.length) {
                        dateHtml = dateCell.clone().html();
                    }
                }

                if (filterType === 'attribute') {
                    var thisEventHtml = buildThisEventCorrelationCard(
                        currentEventDateSafe,
                        currentEventOrg,
                        currentEventId,
                        currentEventInfo,
                        metaBlockHtml,
                        attrCategory,
                        attrType,
                        attrValue,
                        idsHtml,
                        correlationHtml,
                        sightingsHtml,
                        distributionHtml,
                        dateHtml
                    );

                    // Insert "This Event" card before the first correlation card
                    var container = $('#correlations-table-container .beta-correlations-container');
                    if (container.length) {
                        container.prepend(thisEventHtml);
                    } else {
                        $('#correlations-table-container').prepend(thisEventHtml);
                    }
                }

                // Show filter banner above the table
                $('#correlations-table-filter-msg').text('<?php echo __('Showing correlations for'); ?>: ' + attrValue);
                $('#correlations-table-filter-banner').css('display', 'flex');
                renderFilteredCorrelationComments(filterValue, filterType);

                $('#correlation-filter-msg').text('<?php echo __('Filtered by'); ?>: ' + attrValue);
                $('#correlation-filter-controls').show();
            } else {
                // Restore all cards and all rows
                cards.show();
                cards.find('.beta-correlation-row').show();
                $('#correlations-table-filter-banner').hide();
                $('#correlations-filter-comments').empty().hide();
                $('#correlation-filter-controls').hide();
            }
        });
    }

    function resetCorrelationFilter() {
        filterCorrelations(null, null);
    }

    // ── Collections widget ────────────────────────────────────────────────────
    // Load all collections that contain this event and render compact linked
    // chips in the Context card. Uses the dedicated read-only JSON endpoint.
    function buildEventCollectionChip(collection, baseurl) {
        var collectionType = collection && collection.type ? String(collection.type) : 'other';
        var collectionTypeClass = collectionType.replace(/[^a-z0-9_-]/gi, '');
        var collectionDescription = collection && collection.description ? String(collection.description).substring(0, 80) : '';
        var link = document.createElement('a');

        link.href = baseurl + '/collections/view/' + encodeURIComponent(collection.id);
        link.className = 'beta-collection-chip beta-type-' + collectionTypeClass;
        link.title = collectionType + (collectionDescription ? ': ' + collectionDescription : '');

        var icon = document.createElement('i');
        icon.className = 'fa fa-folder';
        icon.style.fontSize = '10px';
        icon.style.marginRight = '3px';
        link.appendChild(icon);
        link.appendChild(document.createTextNode(collection && collection.name ? String(collection.name) : ''));

        return link;
    }

    function renderEventCollectionChips(container, collections, baseurl) {
        container.innerHTML = '';
        if (!Array.isArray(collections) || collections.length === 0) {
            return;
        }

        var chips = document.createElement('div');
        chips.className = 'beta-event-collections-chips';
        collections.forEach(function(collection) {
            chips.appendChild(buildEventCollectionChip(collection, baseurl));
        });
        container.appendChild(chips);
    }

    window.loadEventCollections = function() {
        var eventUuid = <?php echo json_encode($event['Event']['uuid']); ?>;
        var baseurl   = <?php echo json_encode($baseurl); ?>;
        var container = document.getElementById('event-collections-container');
        var countNode = document.getElementById('beta-collections-count');
        if (!container) return;

        container.innerHTML = ''; // Clear "Loading…" placeholder immediately

        $.ajax({
            url: baseurl + '/collections/getCollectionsForElements/Event.json',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ uuids: [eventUuid] }),
            dataType: 'json',
            success: function(data) {
                var collections = data && typeof data === 'object' && Array.isArray(data[eventUuid]) ? data[eventUuid] : [];
                if (countNode) {
                    countNode.textContent = String(collections.length);
                }
                renderEventCollectionChips(container, collections, baseurl);
            },
            error: function() {
                container.innerHTML = '';
                if (countNode) {
                    countNode.textContent = '0';
                }
            }
        });
    };
    window.loadEventCollections();
    // ─────────────────────────────────────────────────────────────────────────
</script>
