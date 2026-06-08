<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 *
 * Single teardown routine, used by the disable path (ServiceController) and by
 * the package pre-deinstall. Reverts everything this plugin changed, idempotently:
 *
 *   1. disable our plugin + clear the manage_kea_ddns marker so the kea_sync
 *      injector no-ops on the regeneration below, and revert Kea's DDNS daemon
 *      ONLY if we were the one who enabled it (never touch a user's setting);
 *   2. stop the listener;
 *   3. flush our records from the running Unbound and delete the include file so
 *      they don't reload;
 *   4. regenerate Kea so our injected DDNS settings are gone.
 *
 * Because we never patched any core files, there is nothing else to undo.
 */

require_once("config.inc");
require_once("util.inc");

use OPNsense\Core\Backend;
use OPNsense\Core\Config;

$general = new \OPNsense\KeaUnbound\General();
$backend = new Backend();
$wasManaged = ((string)$general->general->manage_kea_ddns === '1');

// 1. disable plugin + clear marker (+ revert Kea DDNS iff we owned it)
$general->general->enabled = '0';
$general->general->manage_kea_ddns = '0';
$general->serializeToConfig();
if ($wasManaged) {
    $kdns = new \OPNsense\Kea\KeaDdns();
    $kdns->general->enabled = '0';
    $kdns->serializeToConfig();
}
Config::getInstance()->save();

// 2. stop the listener
$backend->configdRun('keaunbound stop');

// 3. flush our records from Unbound, then remove the include file
$include = '/usr/local/etc/unbound.opnsense.d/keaunbound.conf';
if (is_file($include)) {
    $names = [];
    foreach (file($include, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        if (preg_match('/^\s*local-data:\s*"(\S+)\s/', $line, $m)) {
            $names[$m[1]] = true;
        }
    }
    foreach (array_keys($names) as $name) {
        mwexecf('/usr/local/sbin/unbound-control -c %s local_data_remove %s',
            ['/var/unbound/unbound.conf', $name]);
    }
    @unlink($include);
}
// also drop the chroot copy (rebuilt from the source on the next unbound start)
@unlink('/var/unbound/etc/keaunbound.conf');

// 4. regenerate Kea (injector now no-ops since the plugin is disabled; D2 stops
//    if we reverted it)
$backend->configdRun('template reload OPNsense/Kea');
$backend->configdRun('kea restart');

syslog(LOG_NOTICE, 'os-kea-unbound: teardown complete (records flushed, Kea config cleaned'
    . ($wasManaged ? ', Kea DDNS reverted to disabled' : '') . ')');
echo "keaunbound: teardown complete\n";
