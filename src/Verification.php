<?php
/**
 * What verifying one token came to.
 *
 * @package   SugarCommerce\Turnstile
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Turnstile;

/**
 * Class Verification
 *
 * Whether the token passed and, when it did not, one {@see Reason} why —
 * along with whatever Cloudflare said about it: its error codes, the
 * hostname and action the widget was rendered with, the customer data
 * (`cdata`) the page attached, and when the challenge was solved.
 *
 * Cloudflare's fields are kept on a refusal too. A token refused for the
 * wrong hostname is worth logging with the hostname it was for.
 *
 * @since 1.0.0
 */
final readonly class Verification {

	/**
	 * @param bool                    $success       Whether the token is accepted.
	 * @param Reason|null             $reason        Why not; null when it is.
	 * @param list<string>            $codes         Cloudflare's `error-codes`, as sent.
	 * @param string                  $hostname      Where the widget was rendered.
	 * @param string                  $action        The widget's `data-action`.
	 * @param string                  $cdata         The widget's `data-cdata`.
	 * @param \DateTimeImmutable|null $challenged_at When the challenge was solved.
	 */
	private function __construct(
		public bool $success,
		public ?Reason $reason = null,
		public array $codes = array(),
		public string $hostname = '',
		public string $action = '',
		public string $cdata = '',
		public ?\DateTimeImmutable $challenged_at = null,
	) {}

	/**
	 * Refused before Cloudflare said anything about the token.
	 *
	 * @since 1.0.0
	 *
	 * @param Reason $reason Why.
	 *
	 * @return self
	 */
	public static function unanswered( Reason $reason ): self {
		return new self( false, $reason );
	}

	/**
	 * What a siteverify answer says.
	 *
	 * Passed only when `success` is literally `true`; anything else —
	 * false, `"true"`, 1, absent — is {@see Reason::Rejected}. Fields of the
	 * wrong type are read as empty.
	 *
	 * @since 1.0.0
	 *
	 * @param array<mixed> $body The decoded answer, as JSON gave it: any
	 *                          keys, any values, read as nothing when
	 *                          they are not what siteverify sends.
	 *
	 * @return self
	 */
	public static function from_siteverify( array $body ): self {
		$success = true === ( $body['success'] ?? null );
		$codes   = is_array( $body['error-codes'] ?? null ) ? $body['error-codes'] : array();

		return new self(
			$success,
			$success ? null : Reason::Rejected,
			array_values( array_filter( $codes, is_string( ... ) ) ),
			self::text( $body['hostname'] ?? null ),
			self::text( $body['action'] ?? null ),
			self::text( $body['cdata'] ?? null ),
			self::moment( self::text( $body['challenge_ts'] ?? null ) ),
		);
	}

	/**
	 * The same answer, refused.
	 *
	 * For a token Cloudflare accepted that this site does not: the wrong
	 * hostname, the wrong action, too old.
	 *
	 * @since 1.0.0
	 *
	 * @param Reason $reason Why.
	 *
	 * @return self
	 */
	public function refused( Reason $reason ): self {
		return clone( $this, array( 'success' => false, 'reason' => $reason ) );
	}

	/**
	 * Cloudflare's error codes, named.
	 *
	 * @since 1.0.0
	 *
	 * @return list<ErrorCode>
	 */
	public function errors(): array {
		return array_map( ErrorCode::from_cloudflare( ... ), $this->codes );
	}

	/**
	 * Whether Cloudflare gave this error code.
	 *
	 * @since 1.0.0
	 *
	 * @param ErrorCode $code The code.
	 *
	 * @return bool
	 */
	public function has( ErrorCode $code ): bool {
		return in_array( $code, $this->errors(), true );
	}

	/**
	 * Whether this is the site's fault rather than the visitor's.
	 *
	 * True for a missing secret, or one Cloudflare does not recognise. Every
	 * visitor is refused until it is fixed, so say so somewhere an operator
	 * will see it.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function misconfigured(): bool {
		if ( null !== $this->reason && $this->reason->misconfigured() ) {
			return true;
		}

		foreach ( $this->errors() as $error ) {
			if ( $error->misconfigured() ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Seconds since the challenge was solved.
	 *
	 * @since 1.0.0
	 *
	 * @param int|null $now Unix time to measure against. Null uses the clock.
	 *
	 * @return int|null Null when Cloudflare did not say. Never negative: a
	 *                  timestamp a little ahead of this server's clock is
	 *                  zero seconds old.
	 */
	public function age( ?int $now = null ): ?int {
		return null === $this->challenged_at ? null : max( 0, ( $now ?? time() ) - $this->challenged_at->getTimestamp() );
	}

	/**
	 * A string, or '' for anything else.
	 *
	 * @param mixed $value A decoded JSON value.
	 *
	 * @return string
	 */
	private static function text( mixed $value ): string {
		return is_string( $value ) ? $value : '';
	}

	/**
	 * An ISO 8601 timestamp, such as `2026-10-22T15:14:30.096Z`.
	 *
	 * Only that shape: the date parser would otherwise take "now" or
	 * "+1 year" as a time, and an age check would believe it.
	 *
	 * @param string $value The timestamp.
	 *
	 * @return \DateTimeImmutable|null Null when it is not one.
	 */
	private static function moment( string $value ): ?\DateTimeImmutable {
		if ( 1 !== preg_match( '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})$/D', $value ) ) {
			return null;
		}

		try {
			return new \DateTimeImmutable( $value );
		} catch ( \Exception ) {
			return null;
		}
	}
}
