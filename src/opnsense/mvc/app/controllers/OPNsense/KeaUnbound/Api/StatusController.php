<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 */

namespace OPNsense\KeaUnbound\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\KeaUnbound\General;
use OPNsense\Kea\KeaDdns;

/**
 * Read-only status for the Status page: listener health, record count, TSIG
 * state, whether we manage Kea's DDNS, and recent log lines.
 */
class StatusController extends ApiControllerBase
{
    private const INCLUDE_FILE = '/usr/local/etc/unbound.opnsense.d/keaunbound.conf';
    private const LOGFILE = '/var/log/keaunbound/keaunbound.log';

    public function getAction()
    {
        $general = new General();
        $kdns = new KeaDdns();

        // listener health via configd (portable; no posix extension needed)
        $running = false;
        try {
            $statusOut = (string)(new Backend())->configdRun('keaunbound status');
            $running = stripos($statusOut, 'not running') === false
                && stripos($statusOut, 'running') !== false;
        } catch (\Exception $e) {
            $running = false;
        }

        // count local-data records in our include file
        $records = 0;
        if (is_file(self::INCLUDE_FILE)) {
            foreach (@file(self::INCLUDE_FILE) ?: [] as $line) {
                if (strpos(ltrim($line), 'local-data:') === 0) {
                    $records++;
                }
            }
        }

        // recent log lines
        $recent = [];
        if (is_file(self::LOGFILE)) {
            $lines = @file(self::LOGFILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
            $recent = array_slice($lines, -12);
        }

        $tsig = (string)$general->general->tsig_enabled === '1'
            ? (string)$general->general->tsig_algorithm : 'off';

        // resolve the effective qualifying suffix: when blank, Kea/D2 falls back
        // to the firewall's system domain, so surface that actual domain here.
        $suffix = trim((string)$general->general->qualifying_suffix);
        $suffixIsDefault = false;
        if ($suffix === '') {
            $suffixIsDefault = true;
            $cfg = Config::getInstance()->object();
            if (isset($cfg->system->domain)) {
                $suffix = (string)$cfg->system->domain;
            }
        }

        return [
            'enabled' => (string)$general->general->enabled,
            'listener_running' => $running,
            'listener_port' => (string)$general->general->listener_port,
            'records' => $records,
            'tsig' => $tsig,
            'qualifying_suffix' => $suffix,
            'qualifying_suffix_is_default' => $suffixIsDefault,
            'kea_ddns_enabled' => (string)$kdns->general->enabled,
            'kea_ddns_managed' => (string)$general->general->manage_kea_ddns,
            'recent_log' => $recent,
        ];
    }
}
