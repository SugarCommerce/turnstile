# Turnstile

Server-side verification of Cloudflare Turnstile tokens that fails closed: no secret, no answer, a slow answer or an unreadable one is a refusal, and a token minted for another site, another form or too long ago is refused too.

## Why

The widget on the page proves nothing by itself. It puts a token in the form, and only Cloudflare's `siteverify` endpoint can say whether that token is real. The call is one POST; the gaps are around it:

- **Failing open.** "No secret configured, so let everybody through — development works out of the box" is the same code path as a production deploy with a missing variable. Here a missing secret refuses every token, and says why.
- **An outage reads as a pass.** A timeout, a 502, or Cloudflare's own interstitial page in place of JSON has not said yes. Each is a refusal.
- **A token is not tied to your site.** Cloudflare accepts a valid token from any page that has your sitekey, including one somebody else hosts. It tells you the hostname; you have to check it.
- **Or to your form.** A token solved on the newsletter form is just as valid at checkout unless each widget has an action and the server checks it.
- **Or to the last minute.** Cloudflare honours a token for five minutes. Some forms want less.

## Features

- 🔒 **Fails closed, every way** — no secret, no token, an oversized token, unreachable, timed out, non-200, unreadable, `success:false`.
- 🧾 **`Verification`, not a bool** — success, one `Reason` when refused, Cloudflare's error codes, the hostname, action, `cdata` and when the challenge was solved.
- 🏷️ **`ErrorCode`** — Cloudflare's `error-codes` named, with `misconfigured()` for the ones that are the site's fault and `worth_retrying()` for the one that is Cloudflare's.
- 🌐 **Hostname, action and age** — `for_hostnames()`, `for_action()` and `within()`, each a copy, so one configured instance serves every form.
- ⏱️ **A five-second timeout** — a visitor is waiting on the form, and a refusal is the answer when it runs out.
- 🧪 **`is_test_secret()`** — so an application can refuse to boot with Cloudflare's always-pass key outside development.
- 🔐 **Secret and token kept out of stack traces** with `#[\SensitiveParameter]`.

## Requirements

PHP 8.5+, [`sugarcommerce/http-client`](https://github.com/sugarcommerce/http-client).

## Installation

```bash
composer require sugarcommerce/turnstile
```

## Usage

```php
use SugarCommerce\Turnstile\Turnstile;

$turnstile = ( new Turnstile( $secret ) )
    ->for_hostnames( 'shop.example.com', 'www.shop.example.com' );

if ( ! $turnstile->for_action( 'checkout' )->passes( $_POST[ Turnstile::FIELD ] ?? null, $client_ip ) ) {
    // Refused. Render a fresh widget; a token is good for one try.
}
```

When the reason matters — for a log, or to tell a broken configuration from a bot:

```php
use SugarCommerce\Turnstile\{ErrorCode, Reason};

$result = $turnstile->for_action( 'login' )->within( 120 )->verify( $token, $client_ip );

if ( ! $result->success ) {
    if ( $result->misconfigured() ) {
        // No secret, or Cloudflare does not recognise it: every visitor is
        // being refused. Alert somebody.
    }

    log_refusal( $result->reason->value, $result->codes, $result->hostname );
    // 'wrong_hostname', [], 'phish.example.net'
}

$result->cdata;           // whatever the page put in data-cdata
$result->challenged_at;   // ?DateTimeImmutable
$result->age();           // seconds since it was solved, or null
```

| `Reason` | Meaning |
|---|---|
| `NoSecret` | No secret key; nothing was sent. |
| `NoToken` | The form came back without a token; nothing was sent. |
| `TokenTooLong` | Over 2048 characters, longer than Cloudflare issues; nothing was sent. |
| `Unreachable` | Could not connect, or no answer within the timeout. |
| `HttpError` | An answer other than 200. Any error codes with it are kept. |
| `Unreadable` | Not JSON, or no boolean `success`. |
| `Rejected` | Cloudflare said no — see `$result->codes` / `errors()`. |
| `WrongHostname` | Cloudflare said yes, for a token from a hostname not named. |
| `WrongAction` | Cloudflare said yes, for a widget with another `data-action`. |
| `Expired` | Cloudflare said yes, for a challenge older than `within()` allows, or undated. |

Expectations can also be given to the constructor, along with the timeout:

```php
new Turnstile( $secret, $http, hostnames: array( 'shop.example.com' ), action: 'checkout', max_age: 120, timeout: 5 );
```

To retry after `ErrorCode::InternalError`, pass the same `$idempotency_key` (a UUID) to `verify()` both times, so the retry is not refused as a duplicate.

`$ip` is sent as `remoteip` only when it is a valid IP address; pass the client address your proxy setup trusts, not a raw `X-Forwarded-For`.

## The widget

On the page:

```html
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

<form method="post">
    <div class="cf-turnstile" data-sitekey="<sitekey>" data-action="checkout"></div>
    <!-- the widget adds <input type="hidden" name="cf-turnstile-response"> -->
</form>
```

`data-action` is what `for_action()` checks: letters, digits, `_` and `-`, up to 32 characters. `data-cdata` comes back as `$result->cdata`.

With a Content Security Policy, the script and the challenge iframe both come from Cloudflare:

```
script-src https://challenges.cloudflare.com;
frame-src  https://challenges.cloudflare.com;
```

Add them to what the policy already allows. With a nonce-based `script-src`, give the `<script>` tag the nonce.

## Testing without real keys

Cloudflare publishes keys that always give the same answer, for development and automated tests:

| Sitekey | Widget |
|---|---|
| `1x00000000000000000000AA` | Always passes (visible) |
| `2x00000000000000000000AB` | Always blocks (visible) |
| `1x00000000000000000000BB` | Always passes (invisible) |
| `2x00000000000000000000BB` | Always blocks (invisible) |
| `3x00000000000000000000FF` | Forces an interactive challenge (visible) |

| Secret key | `siteverify` |
|---|---|
| `1x0000000000000000000000000000000AA` | Always passes |
| `2x0000000000000000000000000000000AA` | Always fails |
| `3x0000000000000000000000000000000AA` | Fails with `timeout-or-duplicate` — "already spent" |

Test widgets produce the dummy token `XXXX.DUMMY.TOKEN.XXXX`, which test secrets accept and real secrets refuse. Test secrets answer with a placeholder hostname rather than yours, so leave `for_hostnames()` off while using them.

An always-pass secret in production is the check switched off. Refuse it:

```php
if ( 'production' === $env && Turnstile::is_test_secret( $secret ) ) {
    throw new RuntimeException( 'TURNSTILE_SECRET_KEY is a Cloudflare test key.' );
}
```

In a test suite, nothing needs to reach Cloudflare at all — hand the constructor an `HttpClient\Fake`:

```php
use SugarCommerce\HttpClient\{Fake, Response};

$http = Fake::strict()->on( 'POST', Turnstile::ENDPOINT, new Response( true, 200, '{"success":true,"hostname":"shop.example.com","action":"checkout"}' ) );

new Turnstile( 'secret', $http );
```

## Testing

```bash
composer install
composer test
```

85 tests, all against `HttpClient\Fake` — nothing reaches Cloudflare. A token passing with every field read; the form posted; an address that is not one left out; every way of failing closed — no secret, no token, an oversized token, unreachable, timed out, non-200, not JSON, `success` that is not literally `true`, `success:false`; Cloudflare's error codes named, unknown ones included; hostname, action and age enforcement, with undated and slightly-future challenges; Cloudflare's test secrets; and `#[\SensitiveParameter]` and `#[\NoDiscard]` where they belong.

## License

GPL-2.0-or-later
