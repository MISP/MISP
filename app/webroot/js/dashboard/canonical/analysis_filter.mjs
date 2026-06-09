// `analysis_filter` canonical type (PRD §5.5).
//
// Multi-select picker for MISP's three event analysis values.
// Wire shape: int array, subset of {0..2}. `Event::fetchEvent`
// doesn't natively accept `analysis` as a filter input — the
// consumer widget applies the filter as a PHP post-filter against
// the ACL-filtered fetchEvent result set (same pattern as
// threat_level_filter; see EventStreamWidget).
//
// Picker behaviour shared with distribution_filter and
// threat_level_filter via the enum_picker factory — this module is
// a thin shell over the factory call.

import { makeEnumPicker } from './enum_picker.mjs';

// MISP's `Event.analysis` enum.
const LEVELS_DEFINITION = [
  { value: 0, label: 'Initial',  hint: 'Just created' },
  { value: 1, label: 'Ongoing',  hint: 'Population in progress' },
  { value: 2, label: 'Complete', hint: 'Creation finished' },
];

const picker = makeEnumPicker({
  key: 'analysis_filter',
  label: 'Analysis',
  levels: LEVELS_DEFINITION,
  valueAttr: 'data-analysis-level',
  rootClass: 'misp-analysis-filter',
  togglesClass: 'misp-enum-toggles',
  toggleClass: 'misp-enum-toggle',
  helpText: 'Filter events by analysis stage. Empty selection = no filter (any stage matches).',
});

export const KEY = picker.KEY;
export const LABEL = picker.LABEL;
export const LEVELS = picker.LEVELS;
export const equal = picker.equal;
export const displayLabel = picker.displayLabel;
export const buildField = picker.buildField;
export const readValue = picker.readValue;
