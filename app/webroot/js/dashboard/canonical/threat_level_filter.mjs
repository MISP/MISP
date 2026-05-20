// `threat_level_filter` canonical type (PRD §5.5).
//
// Multi-select picker for MISP's four event threat-level values.
// Wire shape: int array, subset of {1..4}. `Event::fetchEvent`
// doesn't natively accept `threat_level_id` — the consumer widget
// applies the filter as a PHP post-filter against the ACL-filtered
// fetchEvent result set (see EventStreamWidget).
//
// Picker behaviour shared with distribution_filter and
// analysis_filter via the enum_picker factory.

import { makeEnumPicker } from './enum_picker.mjs';

// MISP's `threat_level_id` enum. Order mirrors the Events index
// filter dropdown.
const LEVELS_DEFINITION = [
  { value: 1, label: 'High',      hint: 'High — sophisticated APT / 0-day' },
  { value: 2, label: 'Medium',    hint: 'Medium — APT malware' },
  { value: 3, label: 'Low',       hint: 'Low — mass-malware' },
  { value: 4, label: 'Undefined', hint: 'Undefined — no threat level set' },
];

const picker = makeEnumPicker({
  key: 'threat_level_filter',
  label: 'Threat level',
  levels: LEVELS_DEFINITION,
  valueAttr: 'data-threat-level',
  rootClass: 'misp-threat-level-filter',
  togglesClass: 'misp-threat-level-toggles',
  toggleClass: 'misp-threat-level-toggle',
  helpText: 'Filter events by threat level. Empty selection = no filter (any level matches).',
});

export const KEY = picker.KEY;
export const LABEL = picker.LABEL;
export const LEVELS = picker.LEVELS;
export const equal = picker.equal;
export const displayLabel = picker.displayLabel;
export const buildField = picker.buildField;
export const readValue = picker.readValue;
