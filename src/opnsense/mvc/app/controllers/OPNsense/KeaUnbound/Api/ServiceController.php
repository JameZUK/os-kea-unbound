<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 */

namespace OPNsense\KeaUnbound\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Service control for the Kea Unbound DDNS listener.
 *
 * Maps start/stop/restart/status onto the `keaunbound` configd service. We
 * override reconfigure so it just (re)starts the listener — this plugin has no
 * config-generation template, and start.py reads settings from config.xml
 * directly. Phase 4 will extend reconfigure to also enable Kea's DDNS daemon and
 * trigger a Kea reconfigure so the DDNS config is regenerated.
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
        if ((string)(new \OPNsense\KeaUnbound\General())->general->enabled === '1') {
            $backend->configdRun('keaunbound restart');
        } else {
            $backend->configdRun('keaunbound stop');
        }
        return ['status' => 'ok'];
    }
}
