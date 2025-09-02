<?php

namespace Nullpobug\Django\Signing\Tests;

use RuntimeException;
use PHPUnit\Framework\TestCase;
use Nullpobug\Django\Signing\TimestampSigner;
use Nullpobug\Django\Signing\Signer;
use Nullpobug\Django\Signing\Utils;

class TimestampSignerTest extends TestCase
{
    protected TimestampSigner $signer;

    public function setUp(): void
    {
        // Use a fixed secret for reproducibility
        $this->signer = new TimestampSigner('test-secret');
    }

    public function testSignAndUnsign(): void
    {
        $value = 'foobar';
        $signed = $this->signer->sign($value);
        $unsigned = $this->signer->unsign($signed);
        $this->assertSame($value, $unsigned);
    }

    public function testSignAddsTimestamp(): void
    {
        $value = 'hello';
        $signed = $this->signer->sign($value);
        $parts = explode($this->signer->sep, $signed);
        $this->assertCount(3, $parts);

        [$actualValue, $actualTimestamp, $actualSignature] = $parts;
        $this->assertSame($value, $actualValue);
        $this->assertNotEmpty($actualTimestamp);
        $this->assertNotEmpty($actualSignature);
    }

    public function testUnsignWithMaxAgeValid(): void
    {
        $value = 'bar';
        $signed = $this->signer->sign($value);
        // Should not throw
        $result = $this->signer->unsign($signed, 10);
        $this->assertSame($value, $result);
    }

    public function testUnsignWithMaxAgeExpired(): void
    {
        $value = 'baz';
        $salt = 'test.salt';
        // Manually create a signed value with an old timestamp
        $oldTimestamp = Utils::b62_encode(time() - 1000); // @phpstan-ignore argument.type
        $valueWithTs = $value . $this->signer->sep . $oldTimestamp;
        $signed = (new Signer('test-secret', $salt))->sign($valueWithTs);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Signature has expired');

        $signer = new TimestampSigner('test-secret', $salt);
        $signer->unsign($signed, 1);
    }

    public function testUnsignBadFormat(): void
    {
        $badSigned = 'badvalue';
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Bad signature format');
        $this->signer->unsign($badSigned);
    }

    public function testTimestampReturnsCorrectValue(): void
    {
        $value = 'abc';
        $signed = $this->signer->sign($value);
        $parts = explode($this->signer->sep, $signed);
        $expectedTimestamp = Utils::b62_decode($parts[1]);
        $actualTimestamp = $this->signer->timestamp($signed);
        $this->assertSame($expectedTimestamp, $actualTimestamp);
    }

    public function testTimestampBadFormat(): void
    {
        $badSigned = 'foo.bar';
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Bad signature format');
        $this->signer->timestamp($badSigned);
    }
}
