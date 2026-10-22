<?php
/**
 * Verification and error code test suite.
 *
 * @package   SugarCommerce\Turnstile
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace SugarCommerce\Turnstile\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\Turnstile\{ErrorCode, Reason, Verification};

/**
 * Class VerificationTest
 *
 * Reading siteverify's answer, without a client in sight.
 */
final class VerificationTest extends TestCase {

	/* ─── Reading an answer ─────────────────────────────────────────── */

	public function test_only_a_literal_true_is_success(): void {
		$this->assertTrue( Verification::from_siteverify( array( 'success' => true ) )->success );

		foreach ( array( false, 'true', 1, null, array( true ) ) as $not ) {
			$result = Verification::from_siteverify( array( 'success' => $not ) );

			$this->assertFalse( $result->success, var_export( $not, true ) );
			$this->assertSame( Reason::Rejected, $result->reason );
		}

		$this->assertSame( Reason::Rejected, Verification::from_siteverify( array() )->reason );
	}

	public function test_fields_of_the_wrong_type_read_as_empty(): void {
		$result = Verification::from_siteverify( array(
			'success'      => true,
			'hostname'     => array( 'a' ),
			'action'       => 7,
			'cdata'        => null,
			'challenge_ts' => 1792670400,
			'error-codes'  => array( 'bad-request', 3, null, array( 'x' ) ),
		) );

		$this->assertSame( '', $result->hostname );
		$this->assertSame( '', $result->action );
		$this->assertSame( '', $result->cdata );
		$this->assertNull( $result->challenged_at );
		$this->assertNull( $result->age( 1792670400 ) );
		$this->assertSame( array( 'bad-request' ), $result->codes );
	}

	public function test_error_codes_that_are_not_a_list_are_none(): void {
		$this->assertSame( array(), Verification::from_siteverify( array( 'success' => false, 'error-codes' => 'bad-request' ) )->codes );
	}

	/**
	 * @return array<string, array{string, string}>
	 */
	public static function timestamps(): array {
		return array(
			'milliseconds, zulu' => array( '2026-10-22T11:59:00.096Z', '2026-10-22T11:59:00.096000+00:00' ),
			'whole seconds'      => array( '2026-10-22T11:59:00Z', '2026-10-22T11:59:00.000000+00:00' ),
			'an offset'          => array( '2026-10-22T13:59:00+02:00', '2026-10-22T11:59:00.000000+00:00' ),
			'nanoseconds'        => array( '2026-10-22T11:59:00.123456789Z', '2026-10-22T11:59:00.123456+00:00' ),
		);
	}

	#[DataProvider( 'timestamps' )]
	public function test_challenge_timestamps_are_read( string $sent, string $read ): void {
		$at = Verification::from_siteverify( array( 'success' => true, 'challenge_ts' => $sent ) )->challenged_at;

		$this->assertSame( $read, $at?->setTimezone( new \DateTimeZone( 'UTC' ) )->format( 'Y-m-d\TH:i:s.uP' ) );
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function not_timestamps(): array {
		return array(
			'now'          => array( 'now' ),
			'relative'     => array( '+1 year' ),
			'date only'    => array( '2026-10-22' ),
			'no zone'      => array( '2026-10-22T11:59:00' ),
			'impossible'   => array( '2026-13-45T11:59:00Z' ),
			'trailing'     => array( "2026-10-22T11:59:00Z\n" ),
		);
	}

	#[DataProvider( 'not_timestamps' )]
	public function test_anything_else_is_no_timestamp( string $sent ): void {
		$this->assertNull( Verification::from_siteverify( array( 'success' => true, 'challenge_ts' => $sent ) )->challenged_at );
	}

	/* ─── Refusing ──────────────────────────────────────────────────── */

	public function test_a_refusal_keeps_what_cloudflare_said(): void {
		$accepted = Verification::from_siteverify( array( 'success' => true, 'hostname' => 'phish.example.net', 'action' => 'login', 'cdata' => 'c' ) );
		$refused  = $accepted->refused( Reason::WrongHostname );

		$this->assertTrue( $accepted->success, 'The original is unchanged.' );
		$this->assertFalse( $refused->success );
		$this->assertSame( Reason::WrongHostname, $refused->reason );
		$this->assertSame( array( 'phish.example.net', 'login', 'c' ), array( $refused->hostname, $refused->action, $refused->cdata ) );
	}

	public function test_unanswered_has_nothing_but_the_reason(): void {
		$result = Verification::unanswered( Reason::Unreachable );

		$this->assertFalse( $result->success );
		$this->assertSame( Reason::Unreachable, $result->reason );
		$this->assertSame( array(), $result->codes );
		$this->assertSame( '', $result->hostname );
		$this->assertNull( $result->challenged_at );
		$this->assertFalse( $result->misconfigured() );
	}

	/* ─── Error codes ───────────────────────────────────────────────── */

	/**
	 * @return array<string, array{string, ErrorCode}>
	 */
	public static function codes(): array {
		return array(
			'missing-input-secret'   => array( 'missing-input-secret', ErrorCode::MissingInputSecret ),
			'invalid-input-secret'   => array( 'invalid-input-secret', ErrorCode::InvalidInputSecret ),
			'invalid-parsed-secret'  => array( 'invalid-parsed-secret', ErrorCode::InvalidParsedSecret ),
			'invalid-widget-id'      => array( 'invalid-widget-id', ErrorCode::InvalidWidgetId ),
			'missing-input-response' => array( 'missing-input-response', ErrorCode::MissingInputResponse ),
			'invalid-input-response' => array( 'invalid-input-response', ErrorCode::InvalidInputResponse ),
			'timeout-or-duplicate'   => array( 'timeout-or-duplicate', ErrorCode::TimeoutOrDuplicate ),
			'bad-request'            => array( 'bad-request', ErrorCode::BadRequest ),
			'internal-error'         => array( 'internal-error', ErrorCode::InternalError ),
			'a new one'              => array( 'brand-new-error', ErrorCode::Unknown ),
			'our placeholder'        => array( 'unknown', ErrorCode::Unknown ),
			'wrong case'             => array( 'Bad-Request', ErrorCode::Unknown ),
			'empty'                  => array( '', ErrorCode::Unknown ),
		);
	}

	#[DataProvider( 'codes' )]
	public function test_cloudflares_codes_are_named( string $code, ErrorCode $named ): void {
		$this->assertSame( $named, ErrorCode::from_cloudflare( $code ) );
	}

	public function test_only_secret_and_widget_codes_are_the_sites_fault(): void {
		$sites = array( ErrorCode::MissingInputSecret, ErrorCode::InvalidInputSecret, ErrorCode::InvalidParsedSecret, ErrorCode::InvalidWidgetId );

		foreach ( ErrorCode::cases() as $code ) {
			$this->assertSame( in_array( $code, $sites, true ), $code->misconfigured(), $code->value );
		}
	}

	public function test_only_an_internal_error_is_worth_retrying(): void {
		foreach ( ErrorCode::cases() as $code ) {
			$this->assertSame( ErrorCode::InternalError === $code, $code->worth_retrying(), $code->value );
		}
	}

	public function test_only_a_missing_secret_is_a_reason_that_is_the_sites_fault(): void {
		foreach ( Reason::cases() as $reason ) {
			$this->assertSame( Reason::NoSecret === $reason, $reason->misconfigured(), $reason->value );
		}
	}

	public function test_misconfigured_reads_the_codes(): void {
		$this->assertTrue( Verification::from_siteverify( array( 'success' => false, 'error-codes' => array( 'timeout-or-duplicate', 'invalid-widget-id' ) ) )->misconfigured() );
		$this->assertFalse( Verification::from_siteverify( array( 'success' => false, 'error-codes' => array( 'invalid-input-response' ) ) )->misconfigured() );
	}
}
