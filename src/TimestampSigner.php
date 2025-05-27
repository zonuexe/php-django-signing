<?php

namespace Nullpobug\Django\Signing;

use RuntimeException;
use Nullpobug\Django\Signing\Utils;
use function count;
use function explode;
use function time;

/**
 * TimestampSigner is a class that extends the Signer class to add timestamp
 * functionality to signed values. It allows signing values with a timestamp
 * and unsigning them while checking for expiration based on a maximum age.
 */
class TimestampSigner extends Signer
{
    /**
     * @phpstan-param non-empty-string $sep
     */
    public function __construct(
        string $secret,
        string $salt = 'django.core.signing.TimestampSigner',
        string $sep = ':',
        string $algorithm = 'sha256',
    ) {
        parent::__construct($secret, $salt, $sep, $algorithm);
    }

    public function make_timestamp(): string
    {
        return Utils::b62_encode(time());
    }

    public function sign(string $value): string
    {
        $timestamp = $this->make_timestamp();
        $value_with_ts = $value . $this->sep . $timestamp;
        return parent::sign($value_with_ts);
    }

    public function unsign(string $signed_value, int|null $max_age = null): string
    {
        $result = parent::unsign($signed_value);
        $parts = explode($this->sep, $result);
        if (count($parts) !== 2) {
            throw new RuntimeException("Bad signature format");
        }

        [$value, $ts_b62] = $parts;

        if ($max_age !== null) {
            $timestamp = Utils::b62_decode($ts_b62);
            $age = time() - $timestamp;
            if ($age > $max_age) {
                throw new RuntimeException("Signature has expired");
            }
        }

        return $value;
    }

    public function timestamp(string $signed_value): int
    {
        $parts = explode($this->sep, $signed_value);
        if (count($parts) !== 3) {
            throw new RuntimeException("Bad signature format");
        }
        return Utils::b62_decode($parts[1]);
    }
}
