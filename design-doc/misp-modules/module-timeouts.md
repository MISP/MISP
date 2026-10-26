# Per-module execution timeouts

In **Administration → Server Settings → Plugin Settings**, set
`Plugin.Import_<module>_execution_timeout` to give one import module a longer
execution budget without increasing `Plugin.Import_timeout` for every import.
For example, setting `Plugin.Import_ocr_execution_timeout` to `120` allows the
`ocr` module 120 seconds. Other import modules keep their existing defaults.
The same setting is available for Enrichment, Export, Action and Cortex modules.

MISP uses this budget both for its HTTP client and for the top-level `timeout`
sent to the module server. A module's `config.timeout`, if it has one, remains a
separate setting for that module's own API calls.

The first applicable value wins:

1. An explicit top-level `timeout` supplied by the MISP caller.
2. `Plugin.<family>_<module>_execution_timeout`.
3. The module's `meta.timeout` default returned by `/modules`.
4. `Plugin.<family>_timeout`, with the existing 10-second fallback.

Execution budgets must be positive integer seconds. An unset or zero per-module
setting inherits the module default, or the family timeout when no module
default exists. Invalid module defaults and invalid configured defaults are
ignored; invalid explicit request budgets raise `InvalidArgumentException`
before a request is sent.

Hover requests have their own budget: use
`Plugin.Enrichment_<module>_hover_execution_timeout`, `meta.hover_timeout` and
`Plugin.Enrichment_hover_timeout` (with the existing 5-second fallback), in the
same order. Normal execution defaults do not increase hover timeouts.

## Declaring a module default

A Python module can return optional defaults from its existing `version()`
function. The module server already includes this metadata in `/modules`:

```python
moduleinfo = {
    "version": "1.0",
    "module-type": ["expansion", "hover"],
    "timeout": 120,
    "hover_timeout": 5,
}

def version():
    return moduleinfo
```

MISP displays these defaults in the generated per-module settings. Site settings
can override them. Modules without these keys retain the family timeout.
Discovery metadata is reused within the Module model instance; when discovery
fails, requests still use the family timeout. An explicit request budget or a
positive per-module setting does not require discovery.

These are execution wait limits, not cancellation of the Python worker. PHP,
the web server, reverse proxies and the module's own API clients can impose
additional limits that may also need adjustment for a long-running module.
