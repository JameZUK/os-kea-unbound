<?php

/*
 * Copyright (c) 2026 James (JameZUK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the conditions of the
 * BSD-2-Clause license are met.
 */

namespace OPNsense\KeaUnbound;

use OPNsense\Base\BaseModel;

/**
 * Kea Unbound DDNS general settings model.
 */
class General extends BaseModel
{
    /**
     * Generate a fresh base64 TSIG secret sized for the configured algorithm.
     * Called from the controller when TSIG is enabled but no secret exists yet.
     */
    public function generateTsigSecret(): string
    {
        $algo = (string)$this->general->tsig_algorithm;
        $bytes = 32; // hmac-sha256 default
        if ($algo === 'hmac-sha512') {
            $bytes = 64;
        } elseif ($algo === 'hmac-sha1') {
            $bytes = 20;
        }
        return base64_encode(random_bytes($bytes));
    }

    /**
     * Ensure a TSIG key name and secret exist when TSIG is enabled.
     * Returns true if the model was mutated (caller should save).
     */
    public function ensureTsigKey(): bool
    {
        if ((string)$this->general->tsig_enabled !== '1') {
            return false;
        }
        $changed = false;
        if (trim((string)$this->general->tsig_key_name) === '') {
            $this->general->tsig_key_name = 'keaunbound';
            $changed = true;
        }
        if (trim((string)$this->general->tsig_key_secret) === '') {
            $this->general->tsig_key_secret = $this->generateTsigSecret();
            $changed = true;
        }
        return $changed;
    }
}
