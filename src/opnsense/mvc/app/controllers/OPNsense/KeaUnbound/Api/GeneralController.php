<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * BSD-2-Clause
 */

namespace OPNsense\KeaUnbound\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

/**
 * Settings API for the Kea Unbound DDNS general model.
 *
 * Overrides setAction so the TSIG key is auto-provisioned on save: when TSIG is
 * enabled and no secret exists yet, one is generated and persisted. The user
 * never has to create or paste a key.
 */
class GeneralController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'general';
    protected static $internalModelClass = 'OPNsense\KeaUnbound\General';

    /**
     * Never expose the auto-generated TSIG secret over the API. The settings form
     * does not display or post it, and the listener/injector read it straight from
     * config.xml — so there is no reason for it to appear in /general/get (where it
     * would otherwise be visible in browser devtools, proxies, etc.).
     */
    public function getAction()
    {
        $result = parent::getAction();
        // model fields live under <internalModelName>.general.* (the model's
        // top-level container is itself named "general").
        if (isset($result[static::$internalModelName]['general']['tsig_key_secret'])) {
            $result[static::$internalModelName]['general']['tsig_key_secret'] = '';
        }
        return $result;
    }

    public function setAction()
    {
        if ($this->request->isPost()) {
            // Apply the posted settings onto the model first, then ensure the
            // TSIG key exists before validation/save so it is persisted in the
            // same transaction.
            $mdl = $this->getModel();
            $mdl->setNodes($this->request->getPost(static::$internalModelName));
            $mdl->ensureTsigKey();
            $result = $this->validate($mdl, '', true);
            if ($result['result'] == 'failed') {
                return $result;
            }
            return $this->save($mdl, true);
        }
        return ['result' => 'failed'];
    }
}
