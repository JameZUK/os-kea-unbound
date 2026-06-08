<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 */

namespace OPNsense\KeaUnbound;

/**
 * UI controller for the Settings page. Reached as /ui/keaunbound/general
 * (module keaunbound, controller "general", default action "index").
 */
class GeneralController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->title = gettext('Kea Unbound DDNS');
        $this->view->generalForm = $this->getForm('generalSettings');
        $this->view->pick('OPNsense/KeaUnbound/index');
    }
}
