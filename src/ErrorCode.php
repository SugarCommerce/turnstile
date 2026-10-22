<?php
/**
 * The error codes siteverify answers with.
 *
 * @package   SugarCommerce\Turnstile
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Turnstile;

/**
 * Enum ErrorCode
 *
 * Cloudflare's `error-codes`, named. They fall into three groups, and only
 * the first is the visitor's doing:
 *
 * - **The token.** Fake, expired, or already spent — show the widget again.
 * - **The configuration.** A missing or wrong secret, or a widget that does
 *   not exist. Every visitor fails until somebody fixes it, so log these
 *   loudly; {@see self::misconfigured()} picks them out.
 * - **Cloudflare.** An internal error, which it says may be retried.
 *
 * A code Cloudflare adds later is {@see self::Unknown}, never an exception:
 * the answer is still a refusal, and the raw code is kept on the
 * {@see Verification} for the log.
 *
 * @since 1.0.0
 */
enum ErrorCode: string {

	/**
	 * No secret was sent.
	 */
	case MissingInputSecret = 'missing-input-secret';

	/**
	 * The secret is wrong, does not exist, or is a test secret given a
	 * real token.
	 */
	case InvalidInputSecret = 'invalid-input-secret';

	/**
	 * The secret could not be read.
	 */
	case InvalidParsedSecret = 'invalid-parsed-secret';

	/**
	 * The widget the token came from does not exist.
	 */
	case InvalidWidgetId = 'invalid-widget-id';

	/**
	 * No token was sent.
	 */
	case MissingInputResponse = 'missing-input-response';

	/**
	 * The token is malformed or has expired — usually a made-up one.
	 */
	case InvalidInputResponse = 'invalid-input-response';

	/**
	 * The token was already redeemed, or is over five minutes old.
	 */
	case TimeoutOrDuplicate = 'timeout-or-duplicate';

	/**
	 * The request was malformed.
	 */
	case BadRequest = 'bad-request';

	/**
	 * Cloudflare failed; the request may be retried.
	 */
	case InternalError = 'internal-error';

	/**
	 * A code this library does not know.
	 */
	case Unknown = 'unknown';

	/**
	 * From the code Cloudflare sent.
	 *
	 * @since 1.0.0
	 *
	 * @param string $code One entry of `error-codes`.
	 *
	 * @return self Unknown for anything unrecognised, including our own
	 *              placeholder: Cloudflare saying "unknown" is not a code.
	 */
	public static function from_cloudflare( string $code ): self {
		$known = self::tryFrom( $code );

		return null === $known || self::Unknown === $known ? self::Unknown : $known;
	}

	/**
	 * Whether this is the site's fault rather than the visitor's.
	 *
	 * Every form fails until it is fixed, so it belongs in an alert, not in
	 * a "please try again" message.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function misconfigured(): bool {
		return match ( $this ) {
			self::MissingInputSecret, self::InvalidInputSecret, self::InvalidParsedSecret, self::InvalidWidgetId => true,
			default => false,
		};
	}

	/**
	 * Whether asking Cloudflare again could change the answer.
	 *
	 * Only an internal error. Send the same idempotency key with the retry,
	 * so the token is not counted as spent by the first attempt.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function worth_retrying(): bool {
		return self::InternalError === $this;
	}
}
