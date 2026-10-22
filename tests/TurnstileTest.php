<?php
/**
 * Turnstile test suite.
 *
 * @package   SugarCommerce\Turnstile
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace SugarCommerce\Turnstile\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\HttpClient\{Fake, Response};
use SugarCommerce\Turnstile\{ErrorCode, Reason, Turnstile};

/**
 * Class TurnstileTest
 *
 * Against a double: nothing here reaches challenges.cloudflare.com.
 */
final class TurnstileTest extends TestCase {

	private const string SECRET = '0x4AAAAAAAsecret';
	private const string TOKEN  = 'XXXX.DUMMY.TOKEN.XXXX';

	/**
	 * 2026-10-22T12:00:00Z.
	 */
	private const int NOW = 1792670400;

	private static function answer( array $body, int $status = 200 ): Response {
		return new Response( $status < 300, $status, (string) json_encode( $body ), 'application/json' );
	}

	private static function passed( array $extra = array() ): Response {
		return self::answer( $extra + array(
			'success'      => true,
			'challenge_ts' => '2026-10-22T11:59:00.096Z',
			'hostname'     => 'shop.example.com',
			'error-codes'  => array(),
			'action'       => 'checkout',
			'cdata'        => 'order-42',
		) );
	}

	private static function turnstile( Fake $http, string $secret = self::SECRET ): Turnstile {
		return new Turnstile( $secret, $http, timestamp: self::NOW );
	}

	/* ─── Passing ───────────────────────────────────────────────────── */

	public function test_a_token_cloudflare_accepts_passes_with_what_it_said(): void {
		$http   = Fake::strict()->on( 'POST', Turnstile::ENDPOINT, self::passed() );
		$result = self::turnstile( $http )->verify( self::TOKEN );

		$this->assertTrue( $result->success );
		$this->assertNull( $result->reason );
		$this->assertSame( array(), $result->codes );
		$this->assertSame( 'shop.example.com', $result->hostname );
		$this->assertSame( 'checkout', $result->action );
		$this->assertSame( 'order-42', $result->cdata );
		$this->assertSame( '2026-10-22T11:59:00+00:00', $result->challenged_at?->format( 'c' ) );
		$this->assertSame( 60, $result->age( self::NOW ) );
	}

	public function test_the_secret_token_ip_and_idempotency_key_are_posted_as_a_form(): void {
		$http = Fake::strict()->on( 'POST', Turnstile::ENDPOINT, self::passed() );

		$this->assertTrue( self::turnstile( $http )->verify( self::TOKEN, '203.0.113.7', 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6' )->success );

		$sent = $http->sent( 'POST' );

		parse_str( (string) $sent[0]['body'], $form );

		$this->assertCount( 1, $sent );
		$this->assertSame( array(
			'secret'          => self::SECRET,
			'response'        => self::TOKEN,
			'remoteip'        => '203.0.113.7',
			'idempotency_key' => 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6',
		), $form );
		$this->assertSame( 'application/x-www-form-urlencoded', $sent[0]['headers']['Content-Type'] );
	}

	public function test_an_address_that_is_not_one_is_left_out_rather_than_sent(): void {
		$http = Fake::strict()->on( 'POST', '*', self::passed() );

		$this->assertTrue( self::turnstile( $http )->passes( self::TOKEN, 'unknown, 10.0.0.1' ) );

		parse_str( (string) $http->sent( 'POST' )[0]['body'], $form );

		$this->assertSame( array( 'secret' => self::SECRET, 'response' => self::TOKEN ), $form );
	}

	public function test_an_ipv6_address_is_sent(): void {
		$http = Fake::strict()->on( 'POST', '*', self::passed() );

		$this->assertTrue( self::turnstile( $http )->passes( self::TOKEN, '2001:db8::1' ) );

		parse_str( (string) $http->sent( 'POST' )[0]['body'], $form );

		$this->assertSame( '2001:db8::1', $form['remoteip'] );
	}

	/* ─── Failing closed, before asking ─────────────────────────────── */

	/**
	 * The reference implementation let everybody through when the secret
	 * was unset. Here it is a refusal, and nothing is sent.
	 */
	public function test_no_secret_refuses_without_asking(): void {
		$http   = Fake::strict();
		$result = self::turnstile( $http, '' )->verify( self::TOKEN );

		$this->assertFalse( $result->success );
		$this->assertSame( Reason::NoSecret, $result->reason );
		$this->assertTrue( $result->misconfigured() );
		$this->assertFalse( self::turnstile( $http, '' )->passes( self::TOKEN ) );
		$this->assertFalse( self::turnstile( $http, '' )->configured() );
		$this->assertTrue( self::turnstile( $http )->configured() );
		$this->assertCount( 0, $http->sent() );
	}

	/**
	 * @return array<string, array{string|null}>
	 */
	public static function no_tokens(): array {
		return array( 'null' => array( null ), 'empty' => array( '' ) );
	}

	#[DataProvider( 'no_tokens' )]
	public function test_no_token_refuses_without_asking( ?string $token ): void {
		$http = Fake::strict();

		$this->assertSame( Reason::NoToken, self::turnstile( $http )->verify( $token )->reason );
		$this->assertCount( 0, $http->sent() );
	}

	public function test_a_token_longer_than_cloudflare_issues_is_refused_without_asking(): void {
		$http = Fake::strict()->on( 'POST', '*', self::passed() );

		$this->assertSame( Reason::TokenTooLong, self::turnstile( $http )->verify( str_repeat( 'a', Turnstile::MAX_TOKEN + 1 ) )->reason );
		$this->assertCount( 0, $http->sent() );

		$this->assertTrue( self::turnstile( $http )->verify( str_repeat( 'a', Turnstile::MAX_TOKEN ) )->success, 'Exactly the limit is sent.' );
		$this->assertCount( 1, $http->sent() );
	}

	/* ─── Failing closed, after asking ──────────────────────────────── */

	/**
	 * @return array<string, array{Response, Reason}>
	 */
	public static function bad_answers(): array {
		return array(
			'connection refused'      => array( Response::failure( 'connection refused' ), Reason::Unreachable ),
			'timed out'               => array( Response::failure( 'Operation timed out after 5001 milliseconds' ), Reason::Unreachable ),
			'server error'            => array( new Response( false, 500, 'oops' ), Reason::HttpError ),
			'bad gateway, as json'    => array( self::answer( array( 'success' => true ), 502 ), Reason::HttpError ),
			'a redirect'              => array( new Response( false, 302 ), Reason::HttpError ),
			'200 but empty'           => array( new Response( true, 200 ), Reason::Unreadable ),
			'200 but html'            => array( new Response( true, 200, '<html>Just a moment…</html>' ), Reason::Unreadable ),
			'200 but a json string'   => array( new Response( true, 200, '"success"' ), Reason::Unreadable ),
			'200 with no success'     => array( self::answer( array( 'hostname' => 'shop.example.com' ) ), Reason::Unreadable ),
			'success as a string'     => array( self::answer( array( 'success' => 'true' ) ), Reason::Unreadable ),
			'success as a number'     => array( self::answer( array( 'success' => 1 ) ), Reason::Unreadable ),
			'success false'           => array( self::answer( array( 'success' => false, 'error-codes' => array( 'invalid-input-response' ) ) ), Reason::Rejected ),
		);
	}

	#[DataProvider( 'bad_answers' )]
	public function test_anything_but_a_clear_yes_is_a_refusal( Response $answer, Reason $reason ): void {
		$http   = Fake::strict()->on( 'POST', Turnstile::ENDPOINT, $answer );
		$result = self::turnstile( $http )->verify( self::TOKEN );

		$this->assertFalse( $result->success );
		$this->assertSame( $reason, $result->reason );
		$this->assertFalse( self::turnstile( $http )->passes( self::TOKEN ) );
	}

	public function test_an_unscripted_request_is_a_refusal_not_an_error(): void {
		// Fake::strict() fails anything unscripted, the way a dead network does.
		$this->assertSame( Reason::Unreachable, self::turnstile( Fake::strict() )->verify( self::TOKEN )->reason );
	}

	public function test_the_error_codes_are_kept_and_named(): void {
		$http   = Fake::strict()->on( 'POST', '*', self::answer( array( 'success' => false, 'error-codes' => array( 'timeout-or-duplicate', 'something-new' ) ) ) );
		$result = self::turnstile( $http )->verify( self::TOKEN );

		$this->assertSame( array( 'timeout-or-duplicate', 'something-new' ), $result->codes );
		$this->assertSame( array( ErrorCode::TimeoutOrDuplicate, ErrorCode::Unknown ), $result->errors() );
		$this->assertTrue( $result->has( ErrorCode::TimeoutOrDuplicate ) );
		$this->assertFalse( $result->has( ErrorCode::InternalError ) );
		$this->assertFalse( $result->misconfigured() );
	}

	public function test_a_wrong_secret_is_the_sites_fault(): void {
		$http   = Fake::strict()->on( 'POST', '*', self::answer( array( 'success' => false, 'error-codes' => array( 'invalid-input-secret' ) ) ) );
		$result = self::turnstile( $http )->verify( self::TOKEN );

		$this->assertSame( Reason::Rejected, $result->reason );
		$this->assertTrue( $result->misconfigured() );
	}

	public function test_a_non_200_keeps_the_codes_it_came_with(): void {
		$http   = Fake::strict()->on( 'POST', '*', self::answer( array( 'success' => false, 'error-codes' => array( 'bad-request' ) ), 400 ) );
		$result = self::turnstile( $http )->verify( self::TOKEN );

		$this->assertSame( Reason::HttpError, $result->reason );
		$this->assertSame( array( ErrorCode::BadRequest ), $result->errors() );
	}

	/* ─── Hostname ──────────────────────────────────────────────────── */

	public function test_a_token_from_another_site_is_refused(): void {
		$http   = Fake::strict()->on( 'POST', '*', self::passed( array( 'hostname' => 'phish.example.net' ) ) );
		$result = self::turnstile( $http )->for_hostnames( 'shop.example.com' )->verify( self::TOKEN );

		$this->assertFalse( $result->success );
		$this->assertSame( Reason::WrongHostname, $result->reason );
		$this->assertSame( 'phish.example.net', $result->hostname, 'What it was for is kept, for the log.' );
	}

	public function test_any_named_hostname_is_accepted_without_regard_to_case(): void {
		$http = Fake::strict()->on( 'POST', '*', self::passed( array( 'hostname' => 'Shop.Example.com' ) ) );

		$this->assertTrue( self::turnstile( $http )->for_hostnames( 'example.com', ' SHOP.example.com ' )->passes( self::TOKEN ) );
	}

	public function test_a_missing_hostname_is_refused_when_one_is_expected(): void {
		$http = Fake::strict()->on( 'POST', '*', self::passed( array( 'hostname' => null ) ) );

		$this->assertSame( Reason::WrongHostname, self::turnstile( $http )->for_hostnames( 'shop.example.com' )->verify( self::TOKEN )->reason );
		$this->assertTrue( self::turnstile( $http )->passes( self::TOKEN ), 'With no expectation, any hostname will do.' );
	}

	public function test_hostnames_are_not_wildcards(): void {
		$http = Fake::strict()->on( 'POST', '*', self::passed( array( 'hostname' => 'evil.shop.example.com' ) ) );

		$this->assertSame( Reason::WrongHostname, self::turnstile( $http )->for_hostnames( 'shop.example.com' )->verify( self::TOKEN )->reason );
	}

	/* ─── Action ────────────────────────────────────────────────────── */

	public function test_a_token_from_another_form_is_refused(): void {
		$http = Fake::strict()->on( 'POST', '*', self::passed( array( 'action' => 'newsletter' ) ) );

		$this->assertSame( Reason::WrongAction, self::turnstile( $http )->for_action( 'checkout' )->verify( self::TOKEN )->reason );
		$this->assertTrue( self::turnstile( $http )->for_action( 'newsletter' )->passes( self::TOKEN ) );
	}

	public function test_the_action_is_compared_exactly(): void {
		$http = Fake::strict()->on( 'POST', '*', self::passed( array( 'action' => 'Checkout' ) ) );

		$this->assertSame( Reason::WrongAction, self::turnstile( $http )->for_action( 'checkout' )->verify( self::TOKEN )->reason );
	}

	public function test_a_widget_without_an_action_is_refused_when_one_is_expected(): void {
		$http = Fake::strict()->on( 'POST', '*', self::passed( array( 'action' => '' ) ) );

		$this->assertSame( Reason::WrongAction, self::turnstile( $http )->for_action( 'checkout' )->verify( self::TOKEN )->reason );
	}

	/* ─── Age ───────────────────────────────────────────────────────── */

	/**
	 * @return array<string, array{int, bool}>
	 */
	public static function ages(): array {
		return array(
			'well within'    => array( 120, true ),
			'exactly at'     => array( 60, true ),
			'a second over'  => array( 59, false ),
			'off'            => array( 0, true ),
		);
	}

	#[DataProvider( 'ages' )]
	public function test_a_challenge_solved_too_long_ago_is_refused( int $max_age, bool $passes ): void {
		// Solved at 11:59:00.096; it is now 12:00:00 — sixty seconds.
		$http   = Fake::strict()->on( 'POST', '*', self::passed() );
		$result = self::turnstile( $http )->within( $max_age )->verify( self::TOKEN );

		$this->assertSame( $passes, $result->success );
		$this->assertSame( $passes ? null : Reason::Expired, $result->reason );
	}

	/**
	 * @return array<string, array{mixed}>
	 */
	public static function undated(): array {
		return array(
			'absent'        => array( null ),
			'empty'         => array( '' ),
			'garbage'       => array( 'yesterday' ),
			'a relative'    => array( 'now' ),
			'a number'      => array( self::NOW ),
			'no time zone'  => array( '2026-10-22T11:59:00' ),
		);
	}

	#[DataProvider( 'undated' )]
	public function test_with_a_maximum_age_an_undated_challenge_is_refused( mixed $timestamp ): void {
		$http = Fake::strict()->on( 'POST', '*', self::passed( array( 'challenge_ts' => $timestamp ) ) );

		$this->assertSame( Reason::Expired, self::turnstile( $http )->within( 300 )->verify( self::TOKEN )->reason );
		$this->assertTrue( self::turnstile( $http )->passes( self::TOKEN ), 'Without one, Cloudflare\'s five minutes stand.' );
	}

	public function test_a_challenge_a_little_in_the_future_is_not_negative(): void {
		$http   = Fake::strict()->on( 'POST', '*', self::passed( array( 'challenge_ts' => '2026-10-22T12:00:03Z' ) ) );
		$result = self::turnstile( $http )->within( 30 )->verify( self::TOKEN );

		$this->assertTrue( $result->success );
		$this->assertSame( 0, $result->age( self::NOW ) );
	}

	/* ─── All three ─────────────────────────────────────────────────── */

	public function test_expectations_can_be_given_to_the_constructor(): void {
		$http      = Fake::strict()->on( 'POST', '*', self::passed() );
		$turnstile = new Turnstile( self::SECRET, $http, array( 'shop.example.com' ), 'checkout', 90, timestamp: self::NOW );

		$this->assertTrue( $turnstile->passes( self::TOKEN ) );
		$this->assertSame( Reason::WrongAction, $turnstile->for_action( 'login' )->verify( self::TOKEN )->reason );
		$this->assertSame( Reason::Expired, $turnstile->within( 30 )->verify( self::TOKEN )->reason );
		$this->assertSame( Reason::WrongHostname, $turnstile->for_hostnames( 'other.example.com' )->verify( self::TOKEN )->reason );
	}

	public function test_copies_leave_the_original_alone(): void {
		$http      = Fake::strict()->on( 'POST', '*', self::passed( array( 'action' => 'login' ) ) );
		$turnstile = self::turnstile( $http );

		$this->assertFalse( $turnstile->for_action( 'checkout' )->passes( self::TOKEN ) );
		$this->assertTrue( $turnstile->passes( self::TOKEN ) );
	}

	public function test_cloudflares_refusal_is_reported_before_any_expectation(): void {
		$http = Fake::strict()->on( 'POST', '*', self::answer( array( 'success' => false, 'hostname' => 'phish.example.net', 'error-codes' => array( 'timeout-or-duplicate' ) ) ) );

		$this->assertSame( Reason::Rejected, self::turnstile( $http )->for_hostnames( 'shop.example.com' )->verify( self::TOKEN )->reason );
	}

	/* ─── Timeout ───────────────────────────────────────────────────── */

	public function test_the_timeout_is_short(): void {
		$this->assertSame( 5, Turnstile::TIMEOUT );

		$timeout = ( new \ReflectionClass( Turnstile::class ) )->getConstructor()?->getParameters()[5];

		$this->assertSame( 'timeout', $timeout?->getName() );
		$this->assertSame( Turnstile::TIMEOUT, $timeout?->getDefaultValue() );
	}

	/* ─── Test secrets ──────────────────────────────────────────────── */

	public function test_cloudflares_test_secrets_are_recognised(): void {
		$this->assertTrue( Turnstile::is_test_secret( '1x0000000000000000000000000000000AA' ) );
		$this->assertTrue( Turnstile::is_test_secret( '2x0000000000000000000000000000000AA' ) );
		$this->assertTrue( Turnstile::is_test_secret( '3x0000000000000000000000000000000AA' ) );
		$this->assertFalse( Turnstile::is_test_secret( '0x4AAAAAAABkMYinukE8nzYS_6e1rRrDbQ' ) );
		$this->assertFalse( Turnstile::is_test_secret( '' ) );
	}

	/* ─── Secrets stay out of stack traces ──────────────────────────── */

	/**
	 * @return array<string, array{string, string}>
	 */
	public static function sensitive(): array {
		return array(
			'the secret'         => array( '__construct', 'secret' ),
			'the token'          => array( 'verify', 'token' ),
			'the token, briefly' => array( 'passes', 'token' ),
			'a test secret'      => array( 'is_test_secret', 'secret' ),
		);
	}

	#[DataProvider( 'sensitive' )]
	public function test_secrets_and_tokens_are_sensitive( string $method, string $parameter ): void {
		$found = array_values( array_filter(
			( new \ReflectionMethod( Turnstile::class, $method ) )->getParameters(),
			static fn ( \ReflectionParameter $p ): bool => $parameter === $p->getName()
		) );

		$this->assertCount( 1, $found );
		$this->assertCount( 1, $found[0]->getAttributes( \SensitiveParameter::class ), $method . '( $' . $parameter . ' ) lost #[\SensitiveParameter].' );
	}

	/* ─── Results that must be checked ──────────────────────────────── */

	/**
	 * @return array<string, array{string}>
	 */
	public static function must_check(): array {
		return array( 'verify' => array( 'verify' ), 'passes' => array( 'passes' ) );
	}

	#[DataProvider( 'must_check' )]
	public function test_the_result_must_be_used( string $method ): void {
		$attributes = ( new \ReflectionMethod( Turnstile::class, $method ) )->getAttributes( \NoDiscard::class );

		$this->assertCount( 1, $attributes, $method . ' lost #[\NoDiscard].' );
		$this->assertNotSame( '', $attributes[0]->newInstance()->message );
	}
}
