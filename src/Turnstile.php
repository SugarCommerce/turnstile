<?php
/**
 * Cloudflare Turnstile, checked on the server.
 *
 * @package   SugarCommerce\Turnstile
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\Turnstile;

use SugarCommerce\HttpClient\Client as Http;

/**
 * Class Turnstile
 *
 * The widget on the page proves nothing by itself: it puts a token in the
 * form, and only Cloudflare's siteverify endpoint can say whether that
 * token is real, unspent and recent. This asks it, and then checks the
 * things siteverify reports but leaves to you.
 *
 * What it gets right that is easy not to:
 *
 * - **It fails closed.** No secret, no token, an outage, a timeout, a
 *   non-200, an answer that is not JSON: each is a refusal with its own
 *   {@see Reason}. The usual shortcut — "no secret configured, let
 *   everybody through so development works" — is the same code path as a
 *   production deploy with a missing variable.
 * - **A token is for one site.** Cloudflare accepts a valid token from any
 *   page that has your sitekey, including a page somebody else hosts. Name
 *   your hostnames with {@see self::for_hostnames()} and a token minted
 *   anywhere else is refused.
 * - **A token is for one form.** Give each widget a `data-action` and name
 *   it with {@see self::for_action()}; a token solved on the newsletter
 *   form then cannot be replayed into checkout.
 * - **A token is for a moment.** Cloudflare honours one for five minutes;
 *   {@see self::within()} narrows that.
 * - **Oversized tokens are not sent.** Cloudflare's are at most 2048
 *   characters, so anything longer is refused without a request.
 *
 * Tokens are single-use. Verify once per submission, and render a fresh
 * widget for the next one.
 *
 * @since 1.0.0
 */
final readonly class Turnstile {

	/**
	 * Cloudflare's siteverify endpoint.
	 */
	public const string ENDPOINT = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

	/**
	 * The form field the widget puts its token in.
	 */
	public const string FIELD = 'cf-turnstile-response';

	/**
	 * The longest token Cloudflare issues.
	 */
	public const int MAX_TOKEN = 2048;

	/**
	 * Seconds to wait for Cloudflare.
	 *
	 * Short, because a visitor is waiting on the form, and because a refusal
	 * is the answer when it runs out.
	 */
	public const int TIMEOUT = 5;

	/**
	 * The most of an answer that is read, in bytes.
	 *
	 * A siteverify answer is a few hundred bytes. Anything that runs past
	 * this is not one, and is refused rather than read into memory.
	 */
	public const int MAX_ANSWER = 65536;

	/**
	 * Lower-cased hostnames a token may come from. Empty for any.
	 *
	 * @var list<string>
	 */
	private array $hostnames;

	/**
	 * @since 1.0.0
	 *
	 * @param string        $secret    The widget's secret key.
	 * @param Http          $http      HTTP client. Substitute `HttpClient\Fake` in tests.
	 * @param array<string> $hostnames Hostnames a token may come from. Empty for any.
	 * @param string   $action    The `data-action` a token must carry. '' for any.
	 * @param int      $max_age   Seconds since the challenge was solved. 0 leaves
	 *                            it to Cloudflare, which allows five minutes.
	 * @param int      $timeout   Seconds to wait for Cloudflare. At least one.
	 * @param int|null $timestamp Fixed Unix time, for tests. Null uses the clock.
	 */
	public function __construct(
		#[\SensitiveParameter] private string $secret,
		private Http $http = new Http(),
		array $hostnames = array(),
		private string $action = '',
		private int $max_age = 0,
		private int $timeout = self::TIMEOUT,
		private ?int $timestamp = null,
	) {
		$this->hostnames = self::hostnames( $hostnames );
	}

	/**
	 * Keep the secret out of `var_dump()` and `print_r()`.
	 *
	 * #[\SensitiveParameter] keeps it out of a stack trace; a dumped
	 * object, pasted into a log or a bug report, would print it anyway.
	 *
	 * @since 1.0.0
	 *
	 * @return array{secret: string, hostnames: list<string>, action: string, max_age: int, timeout: int}
	 */
	public function __debugInfo(): array {
		return array(
			'secret'    => '' === $this->secret ? '' : '[redacted]',
			'hostnames' => $this->hostnames,
			'action'    => $this->action,
			'max_age'   => $this->max_age,
			'timeout'   => $this->timeout,
		);
	}

	/**
	 * Whether a secret key is set.
	 *
	 * Verifying without one refuses every token, as it should; this is for
	 * a health check or an admin notice that says why.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function configured(): bool {
		return '' !== $this->secret;
	}

	/* ─── Expectations ──────────────────────────────────────────────── */

	/**
	 * A copy that accepts tokens only from these hostnames.
	 *
	 * Compared without regard to case; no wildcards, so name each one.
	 *
	 * @since 1.0.0
	 *
	 * @param string ...$hostnames Hostnames, such as `shop.example.com`.
	 *
	 * @return self
	 */
	public function for_hostnames( string ...$hostnames ): self {
		return clone( $this, array( 'hostnames' => self::hostnames( $hostnames ) ) );
	}

	/**
	 * A copy that accepts tokens only from widgets with this `data-action`.
	 *
	 * @since 1.0.0
	 *
	 * @param string $action The action, exactly as the widget has it.
	 *
	 * @return self
	 */
	public function for_action( string $action ): self {
		return clone( $this, array( 'action' => $action ) );
	}

	/**
	 * A copy that accepts tokens only for challenges solved this recently.
	 *
	 * @since 1.0.0
	 *
	 * @param int $seconds Seconds. 0 leaves it to Cloudflare.
	 *
	 * @return self
	 */
	public function within( int $seconds ): self {
		return clone( $this, array( 'max_age' => max( 0, $seconds ) ) );
	}

	/* ─── Verifying ─────────────────────────────────────────────────── */

	/**
	 * Ask Cloudflare about a token, then hold it to this site's expectations.
	 *
	 * @since 1.0.0
	 *
	 * @param string|null $token           The form's `cf-turnstile-response`.
	 * @param string      $ip              The visitor's address, or ''. Sent only
	 *                                     when it is a valid IP address.
	 * @param string      $idempotency_key A UUID to send again with a retry,
	 *                                     so the retry is not refused as a
	 *                                     duplicate. '' for none.
	 *
	 * @return Verification
	 */
	#[\NoDiscard( 'A token nobody checks the answer for lets everybody through.' )]
	public function verify( #[\SensitiveParameter] ?string $token, string $ip = '', string $idempotency_key = '' ): Verification {
		if ( '' === $this->secret ) {
			return Verification::unanswered( Reason::NoSecret );
		}

		if ( null === $token || '' === $token ) {
			return Verification::unanswered( Reason::NoToken );
		}

		if ( strlen( $token ) > self::MAX_TOKEN ) {
			return Verification::unanswered( Reason::TokenTooLong );
		}

		$response = $this->http->with_timeout( max( 1, $this->timeout ) )->with_max_bytes( self::MAX_ANSWER )->post(
			self::ENDPOINT,
			http_build_query( array_filter( array(
				'secret'          => $this->secret,
				'response'        => $token,
				'remoteip'        => false === filter_var( $ip, FILTER_VALIDATE_IP ) ? '' : $ip,
				'idempotency_key' => $idempotency_key,
			), static fn ( string $value ): bool => '' !== $value ) ),
			array( 'Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => 'application/json' )
		);

		if ( $response->transport_error() ) {
			return Verification::unanswered( Reason::Unreachable );
		}

		$body = $response->json();

		if ( 200 !== $response->status ) {
			// Keep whatever error codes came with it, for the log.
			return is_array( $body ) ? Verification::from_siteverify( $body )->refused( Reason::HttpError ) : Verification::unanswered( Reason::HttpError );
		}

		if ( ! is_array( $body ) || ! is_bool( $body['success'] ?? null ) ) {
			return Verification::unanswered( Reason::Unreadable );
		}

		return $this->hold( Verification::from_siteverify( $body ) );
	}

	/**
	 * Whether a token passes. verify(), for when the reason does not matter.
	 *
	 * @since 1.0.0
	 *
	 * @param string|null $token The form's `cf-turnstile-response`.
	 * @param string      $ip    The visitor's address, or ''.
	 *
	 * @return bool
	 */
	#[\NoDiscard( 'False means the token was refused.' )]
	public function passes( #[\SensitiveParameter] ?string $token, string $ip = '' ): bool {
		return $this->verify( $token, $ip )->success;
	}

	/**
	 * Whether a secret is one of Cloudflare's test secrets.
	 *
	 * They start `1x` (always passes), `2x` (always fails) or `3x` (always
	 * "already spent"). One that reaches production turns the check off, so
	 * an application can refuse to boot with one outside development.
	 *
	 * @since 1.0.0
	 *
	 * @param string $secret A secret key.
	 *
	 * @return bool
	 */
	public static function is_test_secret( #[\SensitiveParameter] string $secret ): bool {
		return 1 === preg_match( '/^[123]x0{20,}AA$/D', $secret );
	}

	/**
	 * Refuse an accepted token that is not for this site, form or moment.
	 *
	 * @param Verification $answer What Cloudflare said.
	 *
	 * @return Verification
	 */
	private function hold( Verification $answer ): Verification {
		if ( ! $answer->success ) {
			return $answer;
		}

		if ( array() !== $this->hostnames && ! in_array( strtolower( $answer->hostname ), $this->hostnames, true ) ) {
			return $answer->refused( Reason::WrongHostname );
		}

		if ( '' !== $this->action && $answer->action !== $this->action ) {
			return $answer->refused( Reason::WrongAction );
		}

		if ( $this->max_age > 0 && ( $answer->age( $this->timestamp ) ?? PHP_INT_MAX ) > $this->max_age ) {
			return $answer->refused( Reason::Expired );
		}

		return $answer;
	}

	/**
	 * Hostnames, trimmed and lower-cased, blanks dropped.
	 *
	 * @param array<string> $hostnames Hostnames.
	 *
	 * @return list<string>
	 */
	private static function hostnames( array $hostnames ): array {
		return array_values( array_unique( array_filter(
			array_map( static fn ( string $host ): string => strtolower( trim( $host ) ), $hostnames ),
			static fn ( string $host ): bool => '' !== $host
		) ) );
	}
}
