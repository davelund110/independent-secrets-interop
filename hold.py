#!/usr/bin/env python3
"""CLN plugin for interop.py: once `hold_htlcs` is called, every incoming
HTLC is held, committed on both sides, until `release_htlcs`."""
from pyln.client import Plugin

plugin = Plugin()


@plugin.async_hook('htlc_accepted')
def on_htlc_accepted(htlc, onion, request, plugin, **kwargs):
    if not plugin.holding:
        request.set_result({'result': 'continue'})
        return
    plugin.held.append(request)
    plugin.log(f"holding htlc {htlc['payment_hash']}")


@plugin.method('hold_htlcs')
def hold_htlcs(plugin):
    """Hold every incoming HTLC from now on."""
    plugin.holding = True
    return {}


@plugin.method('release_htlcs')
def release_htlcs(plugin):
    """Let every held HTLC through, and stop holding."""
    held, plugin.held = plugin.held, []
    plugin.holding = False
    for request in held:
        request.set_result({'result': 'continue'})
    return {'released': len(held)}


@plugin.init()
def init(options, configuration, plugin):
    plugin.holding = False
    plugin.held = []


plugin.run()
