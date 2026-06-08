<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 */

namespace OPNsense\KeaUnbound;

/**
 * UI controller for the Status page. Reached as /ui/keaunbound/status
 * (module keaunbound, controller "status", default action "index").
 * Distinct from Api\StatusController (the /api/keaunbound/status data endpoint).
 */
class StatusController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->title = gettext('Kea Unbound DDNS - Status');
        $this->view->pick('OPNsense/KeaUnbound/status');
    }
}
