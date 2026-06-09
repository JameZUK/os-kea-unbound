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
    // Fault-isolate the core Kea-DDNS revert: if OPNsense ever renames/removes the
    // KeaDdns model this throws, and we must NOT let it abort teardown — our own
    // disable still has to persist and the listener stop + record flush (steps 2-4)
    // still have to run. Log loudly and carry on.
    try {
        $kdns = new \OPNsense\Kea\KeaDdns();
        $kdns->general->enabled = '0';
        $kdns->serializeToConfig();
    } catch (\Throwable $e) {
        syslog(LOG_ERR, 'os-kea-unbound: could not revert Kea DDNS daemon during teardown ('
            . $e->getMessage() . '); continuing with listener stop + record flush');
    }
}
Config::getInstance()->save();

// 2. stop the listener — and confirm it is actually down before flushing, so an
//    orphaned listener can't re-add records during/after the flush below.
$backend->configdRun('keaunbound stop');
$pidfile = '/var/run/keaunbound/kea-unbound-ddns.pid';
for ($i = 0; $i < 20 && is_file($pidfile); $i++) {
    usleep(250000);
}
if (is_file($pidfile)) {
    syslog(LOG_WARNING, 'os-kea-unbound: listener still appears to be running after stop; '
        . 'flushing records anyway');
}

// 3. flush our records from Unbound, then remove the include file.
//    local_data_remove drops the WHOLE name from the running resolver, so if one of
//    our (dynamic) names is co-located with an OPNsense static record of a different
//    family (a Host Override AAAA vs our dynamic A, say), the remove also evicts that
//    static record from runtime. Re-assert any such static records from
//    host_entries.conf afterwards so they don't vanish until the next Unbound reload.
$include = '/usr/local/etc/unbound.opnsense.d/keaunbound.conf';
if (is_file($include)) {
    $staticByName = [];   // normalised name -> [inner local-data strings]
    foreach (file('/var/unbound/host_entries.conf', FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        if (preg_match('/^\s*local-data:\s*"(.+?)"\s*$/', $line, $m)) {
            $inner = trim($m[1]);
            $nm = strtolower(preg_split('/\s+/', $inner)[0]);
            if (substr($nm, -1) !== '.') {
                $nm .= '.';
            }
            $staticByName[$nm][] = $inner;
        }
    }
    $names = [];
    foreach (file($include, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        if (preg_match('/^\s*local-data:\s*"(\S+)\s/', $line, $m)) {
            $names[$m[1]] = true;
        }
    }
    foreach (array_keys($names) as $name) {
        mwexecf('/usr/local/sbin/unbound-control -c %s local_data_remove %s',
            ['/var/unbound/unbound.conf', $name]);
        $key = strtolower($name);
        if (substr($key, -1) !== '.') {
            $key .= '.';
        }
        foreach ($staticByName[$key] ?? [] as $inner) {
            mwexecf('/usr/local/sbin/unbound-control -c %s local_data %s',
                ['/var/unbound/unbound.conf', $inner]);
        }
    }
    @unlink($include);
}
// also drop the chroot copy (rebuilt from the source on the next unbound start)
@unlink('/var/unbound/etc/keaunbound.conf');

// 4. regenerate Kea (injector now no-ops since the plugin is disabled; D2 stops
//    if we reverted it). Surface a failure: if Kea doesn't actually reload/restart,
//    the running daemon still has the injected DDNS config until the next regen.
$reloadOut = (string)$backend->configdRun('template reload OPNsense/Kea');
$restartOut = (string)$backend->configdRun('kea restart');
if (stripos($reloadOut, 'OK') === false && trim($reloadOut) !== '') {
    syslog(LOG_WARNING, 'os-kea-unbound: Kea template reload may have failed: ' . trim($reloadOut));
}
if (stripos($restartOut, 'error') !== false || stripos($restartOut, 'fail') !== false) {
    syslog(LOG_WARNING, 'os-kea-unbound: Kea restart may have failed: ' . trim($restartOut));
}

syslog(LOG_NOTICE, 'os-kea-unbound: teardown complete (records flushed, Kea config cleaned'
    . ($wasManaged ? ', Kea DDNS reverted to disabled' : '') . ')');
echo "keaunbound: teardown complete\n";
