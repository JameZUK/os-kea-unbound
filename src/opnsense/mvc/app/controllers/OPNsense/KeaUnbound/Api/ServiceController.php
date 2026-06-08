<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 */

namespace OPNsense\KeaUnbound\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

/**
 * Service control for the Kea Unbound DDNS listener.
 *
 * Maps start/stop/restart/status onto the `keaunbound` configd service. We
 * override reconfigure to:
 *   1. ensure Kea's DDNS (D2) daemon is enabled, so Kea emits DNS updates;
 *   2. apply Kea (template reload regenerates keactrl/rc.conf.d, then the Kea
 *      restart triggers the kea_sync pass that runs our injector to point DDNS
 *      at our listener);
 *   3. (re)start our listener.
 * This plugin has no config-generation template of its own; start.py reads
 * settings from config.xml directly.
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = 'OPNsense\KeaUnbound\General';
    protected static $internalServiceTemplate = 'OPNsense/KeaUnbound';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'keaunbound';

    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $backend = new Backend();
        $gen = new \OPNsense\KeaUnbound\General();
        $enabled = (string)$gen->general->enabled === '1';
        if ($enabled) {
            // Record-before-mutate: enable Kea's DDNS daemon only if it is off,
            // and remember that WE enabled it so disable/uninstall can revert it.
            // If the user already had it on, we leave the marker clear and never
            // touch their setting. config.xml writes go through write_config
            // (atomic + auto-backup).
            $kdns = new \OPNsense\Kea\KeaDdns();
            if ((string)$kdns->general->enabled !== '1') {
                $kdns->general->enabled = '1';
                $kdns->serializeToConfig();
                $gen->general->manage_kea_ddns = '1';
                $gen->serializeToConfig();
                Config::getInstance()->save();
                syslog(LOG_NOTICE, 'os-kea-unbound: enabled Kea DDNS (kea-dhcp-ddns) ' .
                    'so leases can be registered in Unbound');
            }
            // Apply Kea (regenerates keactrl/rc.conf.d; the restart runs the
            // kea_sync pass that invokes our injector), then (re)start our listener.
            $backend->configdRun('template reload OPNsense/Kea');
            $backend->configdRun('kea restart');
            $backend->configdRun('keaunbound restart');
        } else {
            // Disable: revert Kea's DDNS only if we were the one who enabled it,
            // then regenerate Kea (our injector self-disables, leaving a clean
            // config) and stop our listener.
            if ((string)$gen->general->manage_kea_ddns === '1') {
                $kdns = new \OPNsense\Kea\KeaDdns();
                $kdns->general->enabled = '0';
                $kdns->serializeToConfig();
                $gen->general->manage_kea_ddns = '0';
                $gen->serializeToConfig();
                Config::getInstance()->save();
                syslog(LOG_NOTICE, 'os-kea-unbound: reverted Kea DDNS to disabled (was ' .
                    'enabled by this plugin)');
                $backend->configdRun('template reload OPNsense/Kea');
                $backend->configdRun('kea restart');
            }
            $backend->configdRun('keaunbound stop');
        }
        return ['status' => 'ok'];
    }

    /**
     * Seed existing Kea leases + reservations into Unbound on demand
     * (the Status page "Sync now" button).
     */
    public function syncAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $output = (new Backend())->configdRun('keaunbound sync');
        return ['status' => 'ok', 'output' => trim((string)$output)];
    }
}
