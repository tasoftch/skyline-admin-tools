<?php

namespace Skyline\Admin\Tool;


use DateTime;
use Skyline\CMS\Security\Tool\AbstractSecurityTool;
use Skyline\Security\Authentication\Validator\Attempt;
use Skyline\Security\Authentication\Validator\Storage\AttemptStorage;
use Skyline\Security\Exception\FailedAttemptException;
use Symfony\Component\HttpFoundation\Request;

class BruteForceTool extends AbstractSecurityTool
{
	const SERVICE_NAME = 'bruteForceTool';

	const MAX_BLOCKING_INTERVAL = 3600;
	const GLOBAL_HASH_STRING = "skyline-cms-global";

	protected $storage;

	/**
	 * BruteForceTool constructor.
	 * @param $file
	 * @param null $username
	 * @param null $password
	 */
	public function __construct($file, $username = NULL, $password = NULL)
	{
		$this->storage = new AttemptStorage($file, 'BF_ATTEMPT', $username, $password);
	}

	/**
	 * Makes a hash of the current client IP Address
	 *
	 * @param Request|null $request
	 * @return string
	 */
	public function getIPAddressHash(Request $request = NULL) {
		return md5( $request ? $request->server->get("REMOTE_ADDR") : $_SERVER["REMOTE_ADDR"] );
	}

	/**
	 * Makes a hash of the requested URI
	 *
	 * @param Request|null $request
	 * @return string
	 */
	public function getURIHash(Request $request = NULL) {
		return md5( $request ? $request->getRequestUri() : $_SERVER["REQUEST_URI"] );
	}

	/**
	 * @param Request|null $request
	 * @param $includeIP
	 * @param $includeURI
	 * @return string
	 * @internal
	 */
	protected function generateHash(Request $request = NULL, $includeIP, $includeURI) {
		if($includeIP && $includeURI)
			return md5($this->getIPAddressHash($request) . ":" . $this->getURIHash($request));
		elseif($includeURI)
			return $this->getURIHash($request);
		elseif($includeIP)
			return $this->getIPAddressHash($request);
		else
			return md5(static::GLOBAL_HASH_STRING);
	}

	/**
	 * Limits the access requests to a resource by identifying it using the client's ip address and/or the requested URI.
	 *
	 * @param int $maximalAttempts
	 * @param int $blockInterval
	 * @param Request|null $request
	 * @param bool $includeIP
	 * @param bool $includeURI
	 * @throws FailedAttemptException
	 */
	public function limitAccess(int $maximalAttempts, int $blockInterval, Request $request = NULL, bool $includeIP = true, bool $includeURI = true) {
		$this->storage->clearAttempts( static::MAX_BLOCKING_INTERVAL );

		$hash = $this->generateHash($request, $includeIP, $includeURI);

		if($attempt = $this->storage->getAttempt($hash)) {
			if($attempt->getDate()->getTimestamp() <= time()-$blockInterval) {
				$this->storage->clearAttempt($attempt);
				goto makeAttempt;
			}

			if($attempt->getTrials() >= $maximalAttempts) {
				$e = new FailedAttemptException("Access got blocked because of too many requests. Please try again later", 403);
				$e->setAttempt($attempt);
				throw $e;
			}
		}

		if($attempt) {
			$attempt = new Attempt($hash, new DateTime(), $attempt->getTrials() + 1);
		} else {
			makeAttempt:
			$attempt = new Attempt($hash, new DateTime(), 1);
		}

		$this->storage->setAttempt($attempt);
	}

	/**
	 * Clears the access limitation if one exists
	 *
	 * @param Request|null $request
	 * @param bool $includeIP
	 * @param bool $includeURI
	 */
	public function clearAccessLimitation(Request $request = NULL, bool $includeIP = true, bool $includeURI = true) {
		$hash = $this->generateHash($request, $includeIP, $includeURI);

		if($attempt = $this->storage->getAttempt($hash)) {
			$this->storage->clearAttempt( $attempt );
		}
	}

	/**
	 * @param Request|null $request
	 * @param bool $includeIP
	 * @param bool $includeURI
	 * @return Attempt|null
	 */
	public function getAccessLimitation(Request $request = NULL, bool $includeIP = true, bool $includeURI = true): ?Attempt {
		$hash = $this->generateHash($request, $includeIP, $includeURI);

		return $this->storage->getAttempt($hash);
	}
}