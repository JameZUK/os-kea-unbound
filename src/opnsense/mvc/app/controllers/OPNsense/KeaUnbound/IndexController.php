<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 */

namespace OPNsense\KeaUnbound;

use OPNsense\Base\IndexController as BaseIndexController;

class IndexController extends BaseIndexController
{
    public function generalAction()
    {
        $this->view->title = gettext('Kea Unbound DDNS');
        $this->view->generalForm = $this->getForm('generalSettings');
        $this->view->pick('OPNsense/KeaUnbound/index');
    }
}
