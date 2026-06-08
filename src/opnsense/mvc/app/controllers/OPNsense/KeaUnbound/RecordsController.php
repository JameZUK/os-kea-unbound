<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 */

namespace OPNsense\KeaUnbound;

/**
 * UI controller for the Records page. Reached as /ui/keaunbound/records
 * (module keaunbound, controller "records", default action "index").
 * Distinct from Api\RecordsController (the /api/keaunbound/records search endpoint).
 */
class RecordsController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->title = gettext('Kea Unbound DDNS - Records');
        $this->view->pick('OPNsense/KeaUnbound/records');
    }
}
