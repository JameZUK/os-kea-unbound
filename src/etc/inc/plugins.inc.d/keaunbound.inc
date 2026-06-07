<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 *
 * Plugin registration for os-kea-unbound (DDNS edition).
 *
 * Phase 3: registers the listener as a supervised service and starts/stops it on
 * boot according to the enabled flag.
 *
 * Phase 4 will add the `kea_sync` hook (to inject DDNS settings into Kea's
 * generated config after kea_configure_do, before the daemon starts) and the
 * auto-enable of Kea's DDNS daemon.
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
