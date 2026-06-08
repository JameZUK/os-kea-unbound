<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 */

namespace OPNsense\KeaUnbound\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Search endpoint for the Records page: returns the DDNS records currently
 * registered in Unbound (enriched with Kea detail) in the bootgrid contract
 * (searchPhrase / sort / current / rowCount in, {total, rows, ...} out).
 *
 * Records live in a file (not a model), so we run the keaunbound `records`
 * action and apply search/sort/paging here rather than via searchBase().
 */
class RecordsController extends ApiControllerBase
{
    public function searchAction()
    {
        $rows = [];
        try {
            $out = (string)(new Backend())->configdRun('keaunbound records');
            $decoded = json_decode($out, true);
            if (is_array($decoded)) {
                $rows = $decoded;
            }
        } catch (\Exception $e) {
            $rows = [];
        }

        $search = (string)$this->request->get('searchPhrase', null, '');
        $sort = $this->request->get('sort', null, []);
        $rowCount = (int)$this->request->get('rowCount', null, 20);
        $current = (int)$this->request->get('current', null, 1);
        if ($current < 1) {
            $current = 1;
        }

        // free-text filter across every field (searchable)
        if ($search !== '') {
            $needle = strtolower($search);
            $rows = array_values(array_filter($rows, function ($r) use ($needle) {
                foreach ($r as $v) {
                    if (strpos(strtolower((string)$v), $needle) !== false) {
                        return true;
                    }
                }
                return false;
            }));
        }

        // single-column sort (sortable headers)
        if (is_array($sort) && !empty($sort)) {
            $col = (string)array_keys($sort)[0];
            $dir = strtolower((string)array_values($sort)[0]) === 'desc' ? -1 : 1;
            usort($rows, function ($a, $b) use ($col, $dir) {
                $av = $a[$col] ?? '';
                $bv = $b[$col] ?? '';
                if (is_numeric($av) && is_numeric($bv)) {
                    $cmp = $av <=> $bv;
                } else {
                    $cmp = strnatcasecmp((string)$av, (string)$bv);
                }
                return $dir * $cmp;
            });
        }

        $total = count($rows);
        if ($rowCount != -1) {
            $rows = array_slice($rows, ($current - 1) * $rowCount, $rowCount);
        }

        return [
            'current' => $current,
            'rowCount' => $rowCount,
            'total' => $total,
            'rows' => array_values($rows),
        ];
    }
}
