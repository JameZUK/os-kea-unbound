<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 */

namespace OPNsense\KeaUnbound;

use OPNsense\Base\IndexController as BaseIndexController;

/**
 * Module default controller — only the bare /ui/keaunbound/ URL resolves here
 * (OPNsense routing: path element 1 = controller, element 2 = action). The real
 * pages are served by their own controllers, each reached at /ui/keaunbound/<name>:
 *   - GeneralController  -> Settings  (/ui/keaunbound/general)
 *   - StatusController   -> Status    (/ui/keaunbound/status)
 *   - RecordsController  -> Records   (/ui/keaunbound/records)
 * The menu (Menu/Menu.xml) links to those, never to the bare URL, so no action is
 * defined here. (The earlier generalAction/statusAction were unreachable dead
 * duplicates of GeneralController/StatusController and have been removed.)
 */
class IndexController extends BaseIndexController
{
}
