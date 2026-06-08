<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 *
 * Plugin registration for os-kea-unbound (DDNS edition).
 *
 * Registers the listener as a supervised service, starts/stops it on boot, and
 * registers a `kea_sync` hook that injects DDNS settings into Kea's generated
 * config. The hook runs as part of `pluginctl -c kea_sync`, after kea.inc's
 * kea_configure_do has regenerated the daemon configs (kea sorts before
 * keaunbound), so our injection always lands on the fresh config and is
 * re-applied on every Kea reconfigure.
 */

function keaunbound_enabled()
{
    $mdl = new \OPNsense\KeaUnbound\General();
    return (string)$mdl->general->enabled === '1';
}

function keaunbound_services()
{
    $services = [];
    if (keaunbound_enabled()) {
        $services[] = [
            'description' => gettext('Kea Unbound DDNS listener'),
            'configd' => [
                'restart' => ['keaunbound restart'],
                'start' => ['keaunbound start'],
                'stop' => ['keaunbound stop'],
            ],
            'name' => 'keaunbound',
            'pidfile' => '/var/run/keaunbound/kea-unbound-ddns.pid',
        ];
    }
    return $services;
}

function keaunbound_configure()
{
    return [
        'bootup' => ['keaunbound_configure_do'],
        'kea_sync' => ['keaunbound_kea_sync'],
    ];
}

function keaunbound_configure_do($verbose = false)
{
    $backend = new \OPNsense\Core\Backend();
    if (keaunbound_enabled()) {
        $backend->configdRun('keaunbound start');
    } else {
        $backend->configdRun('keaunbound stop');
    }
}

/**
 * kea_sync hook: inject our DDNS settings into the just-regenerated Kea configs.
 * Runs after kea.inc's kea_configure_do in the same `pluginctl -c kea_sync` pass.
 * No-op when the plugin is disabled (the injector self-checks config.xml). The
 * command is fixed (no user input); mwexecf escapes the argument regardless.
 */
function keaunbound_kea_sync($verbose = false)
{
    mwexecf('/usr/local/bin/python3 %s', '/usr/local/opnsense/scripts/keaunbound/kea-config-sync.py');
}
