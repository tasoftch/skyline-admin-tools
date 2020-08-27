<?php
/**
 * BSD 3-Clause License
 *
 * Copyright (c) 2020, TASoft Applications
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

namespace Skyline\Admin\Tool;

use Skyline\Admin\Tool\Exception\InternalException;
use Skyline\CMS\Security\Authentication\AuthenticationServiceFactory;
use Skyline\CMS\Security\Tool\Event\UserEvent;
use Skyline\CMS\Security\Tool\PasswordResetTool;
use Skyline\CMS\Security\UserSystem\User;
use Skyline\Kernel\Service\SkylineServiceManager;
use Skyline\Security\Authentication\AuthenticationService;
use Skyline\Security\Identity\IdentityService;
use Skyline\Security\User\UserInterface;
use Symfony\Component\HttpFoundation\Request;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDOResourceInterface;
use Throwable;

class UserTool extends \Skyline\CMS\Security\Tool\UserTool
{
	const ATTRIBUTE_PRENAME = 'prename';
	const ATTRIBUTE_SURNAME = 'surname';
	const ATTRIBUTE_EMAIL = 'email';

	const ATTRIBUTE_INTERNAL = 'internal';
	const ATTRIBUTE_LOGIN_WITH_EMAIL = 'lw-email';

	const ATTRIBUTE_GROUPS = 'groups';
	const ATTRIBUTE_ROLES = 'roles';

	private $loadedUsers = [];

	/** @var UserInterface|null */
	private $currentUser;

	/**
	 * @param int|string|null $user
	 * @return UserInterface|null
	 */
	public function getUser($user = NULL): ?UserInterface
	{
		if($user) {
			if($user instanceof UserInterface) {
				$usr = $user;
				$user = $user->getUsername();
				goto register;
			}

			if(!isset($this->loadedUsers[$user]) && false !== $this->loadedUsers) {
				/** @var AuthenticationService $as */
				if($as = $sm = ServiceManager::generalServiceManager()->get( AuthenticationServiceFactory::AUTHENTICATION_SERVICE )) {
					if($usr = $as->getUserProvider()->loadUserWithToken($user)) {
						register:
						$this->loadedUsers[ $usr->getUsername() ] = $usr;
						if(method_exists($usr, 'getId'))
							$this->loadedUsers[$usr->getId()] = $usr;
						if(method_exists($user, 'getEmail'))
							$this->loadedUsers[$usr->getEmail()] = $usr;
					} else
						$this->loadedUsers[$user] = false;
				} else
					$this->loadedUsers = false;
			}

			return $this->loadedUsers[$user] ?: NULL;
		}
		return $this->currentUser ?? parent::getUser();
	}

	/**
	 * If a user passed, all methods of the user tool are applied to the new current user.
	 * Pass NULL or nothing to reset current user and obtain it from client.
	 *
	 * @param UserInterface|null $user
	 */
	public function setCurrentUser(UserInterface $user = NULL) {
		$this->currentUser = $user;
	}

	/**
	 * Creates a new user (if multiple user system is enabled)
	 *
	 * Additional to username and credential you can specify user attributes like email address or surname.
	 * It is also possible to pass groups and/or roles to directly assign.
	 *
	 * If $install is true, the new user gets transmitted as a simulation of a HTML Form login.
	 *
	 * @param string $username
	 * @param string $plainCredential
	 * @param array|string[] $attributes
	 * @param bool $install
	 * @param int|null $errorCode
	 * @return UserInterface|null
	 *
	 * @throws Throwable
	 * @throws Throwable
	 */
	public function createUser(string $username, string $plainCredential, array $attributes = [], bool $install = false, int &$errorCode = NULL): ?UserInterface {
		/** @var PasswordResetTool $pwt */
		$pwt = ServiceManager::generalServiceManager()->get( PasswordResetTool::SERVICE_NAME );
		if(!$pwt)
			return NULL;

		$options = 0;
		if((isset($attributes[static::ATTRIBUTE_EMAIL]) && ($attributes[static::ATTRIBUTE_LOGIN_WITH_EMAIL] ?? true)) || ($attributes[static::ATTRIBUTE_LOGIN_WITH_EMAIL] ?? false)) {
			$options |= User::OPTION_CAN_LOGIN_WITH_MAIL;
		}

		$this->getPDO()->inject("INSERT INTO SKY_USER (username, credentials, email, prename, surname, options) VALUES (?, ?, ?, ?, ?, ?)")->send([
			$username,
			'#',
			$attributes[ static::ATTRIBUTE_EMAIL ] ?? "",
			$attributes[ static::ATTRIBUTE_PRENAME ] ?? "",
			$attributes[ static::ATTRIBUTE_SURNAME ] ?? "",
			$options
		]);
		if($user = $this->getUser( $username )) {
			if($pwt->updateUserPassword($user, $plainCredential, $errorCode)) {
				if(!$this->disableEvents) {
					$e = new UserEvent();
					$e->setUser($user);
					SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_ADD, $e, $user, $errorCode);
				}

				if(is_array($groups = $attributes[static::ATTRIBUTE_GROUPS] ?? NULL)) {
					$oldU = $this->getUser();
					$this->setCurrentUser($user);
					$this->assignGroups( $groups, false );
					$this->setCurrentUser($oldU);
				}

				if(is_array($roles = $attributes[static::ATTRIBUTE_ROLES] ?? NULL)) {
					$oldU = $this->getUser();
					$this->setCurrentUser($user);
					$this->assignRoles( $roles, false );
					$this->setCurrentUser($oldU);
				}

				if($attributes[static::ATTRIBUTE_INTERNAL] ?? false) {
					$op = User::OPTION_INTERNAL;

					$this->getPDO()->inject("UPDATE SKY_USER SET options = options | $op WHERE username = ?")->send([
						$username
					]);
				}

				if($install) {
					$this->loginWithCredentials($username, $plainCredential);
				}

				return $user;
			}
			$this->getPDO()->inject("DELETE FROM SKY_USER WHERE username = ?")->send([
				$username
			]);
		}
		return NULL;
	}

	/**
	 * Reset and installs a new identity with a given username and credential using the HTML Form challenge.
	 *
	 * Tecnically this method updates the $_POST fields identified by the service management parameters and also the current HTTP requests post fields with the new credentials.
	 *
	 * @param string $username
	 * @param string $plainCredential
	 * @return UserInterface|null
	 */
	public function loginWithCredentials(string $username, string $plainCredential): ?UserInterface {
		$sm = ServiceManager::generalServiceManager();

		$tnf = $sm->getParameter("security.http.post.tokenName");
		$pwf = $sm->getParameter("security.http.post.credentialName");
		/** @var Request $req */
		$req = $sm->serviceExists('request') ? $sm->get("request") : NULL;
		if($req&&$tnf&&$pwf) {
			$is = $this->getIdentityService();
			if($is instanceof IdentityService)
				$is->resetIdentityCache();

			$req->request->set($tnf, $_POST[$tnf] = $username);
			$req->request->set($pwf, $_POST[$pwf] = $plainCredential);
			return $this->getUser();
		}
		return NULL;
	}

	/**
	 * @param $user
	 * @param bool $silent
	 * @return bool|null
	 */
	protected function checkInternal($user, bool $silent = false): ?bool {
		if(is_object($user) && method_exists($user, 'getId'))
			$userd = $user->getId();
		elseif($user instanceof UserInterface)
			$userd = $user->getUsername();
		elseif(is_scalar($user))
			$userd = $user;
		else
			return NULL;

		$raise = function($code, $msg) use ($user, $silent) {
			if(!$silent) {
				throw (new InternalException($msg, $code))->setObject($user);
			}
			return false;
		};

		$options = 0;
		if(is_string($userd)) {
			$options = $this->getPDO()->selectFieldValue("SELECT options FROM SKY_USER WHERE username = ? LIMIT 1", 'options', [$userd]) * 1;
		} elseif(is_numeric($userd)) {
			$options = $this->getPDO()->selectFieldValue("SELECT options FROM SKY_USER WHERE id = $userd LIMIT 1", 'options') * 1;
		} else
			return NULL;

		if($options & User::OPTION_INTERNAL) {
			if(!$silent) {
				throw (new InternalException('User is internal and can not be modified', 403))->setObject($user);
			}
			return true;
		}

		return false;
	}

	/**
	 * Removes a user from the system
	 *
	 * @param UserInterface $user
	 * @throws Throwable
	 */
	public function removeUser(UserInterface $user) {
		$this->checkInternal($user);

		if(!$this->disableEvents) {
			$e = new UserEvent();
			$e->setUser($user);
			SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_REMOVE, $e, $user);
		}

		if(method_exists($user, 'getId')) {
			$uid = $user->getId() * 1;
			remove:
			if($uid) {
				$this->getPDO()->transaction(function() use ($uid) {
					$this->getPDO()->exec("DELETE FROM SKY_USER_GROUP WHERE user = $uid");
					$this->getPDO()->exec("DELETE FROM SKY_USER_ROLE WHERE user = $uid");
					$this->getPDO()->exec("DELETE FROM SKY_USER WHERE id = $uid");
				});
			}
		} else {
			$un = $user->getUsername();
			$uid = $this->getPDO()->selectFieldValue("SELECT id FROM SKY_USER WHERE username = ?", 'id', [$un]) * 1;
			if($uid)
				goto remove;
		}
	}

	/**
	 * Makes membership to specified groups for the current user.
	 *
	 * @param array|null $groups
	 * @param bool $invalidateCurrentSession
	 * @return bool
	 * @throws Throwable
	 */
	public function assignGroups(array $groups = NULL, bool $invalidateCurrentSession = true) {
		if($uid = $this->getUserID()) {
			$this->checkInternal($uid);

			$gt = ServiceManager::generalServiceManager()->get(\Skyline\CMS\Security\Tool\UserGroupTool::SERVICE_NAME);
			if($gt instanceof \Skyline\CMS\Security\Tool\UserGroupTool) {
				if($this->getPDO()->transaction(function() use ($uid, &$groups, $gt, $invalidateCurrentSession) {
					$this->getPDO()->exec("DELETE FROM SKY_USER_GROUP WHERE user = $uid");

					if($groups) {
						$insert = $this->getPDO()->inject("INSERT INTO SKY_USER_GROUP (user, groupid) VALUES ($uid, ?)");

						foreach($groups as &$group) {
							if($group = $gt->getGroup($group))
								$insert->send([$group->getId()]);
						}
					}

					if($invalidateCurrentSession) {
						$o = User::OPTION_INVALIDATE_SESSION;
						$this->getPDO()->exec("UPDATE SKY_USER SET options = (options | $o) WHERE id = $uid");
					}
				})) {
					if(!$this->disableEvents) {
						$e = new UserEvent();
						$e->setUser($u = $this->getUser());
						SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_UPDATE, $e, $u, $groups);
					}
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Assigns new roles to the current user.
	 *
	 * @param array|null $roles
	 * @param bool $invalidateCurrentSession
	 * @return bool
	 * @throws Throwable
	 */
	public function assignRoles(array $roles = NULL, bool $invalidateCurrentSession = true) {
		if($uid = $this->getUserID()) {
			$this->checkInternal($uid);

			$gt = ServiceManager::generalServiceManager()->get(\Skyline\CMS\Security\Tool\UserRoleTool::SERVICE_NAME);
			if($gt instanceof \Skyline\CMS\Security\Tool\UserRoleTool) {
				if($this->getPDO()->transaction(function() use ($uid, &$roles, $gt, $invalidateCurrentSession) {
					$this->getPDO()->exec("DELETE FROM SKY_USER_ROLE WHERE user = $uid");

					if($roles) {
						$insert = $this->getPDO()->inject("INSERT INTO SKY_USER_ROLE (user, role) VALUES ($uid, ?)");

						foreach($roles as &$role) {
							if($role = $gt->getRole($role))
								$insert->send([$role->getId()]);
						}
					}

					if($invalidateCurrentSession) {
						$o = User::OPTION_INVALIDATE_SESSION;
						$this->getPDO()->exec("UPDATE SKY_USER SET options = (options | $o) WHERE id = $uid");
					}
				})) {
					if(!$this->disableEvents) {
						$e = new UserEvent();
						$e->setUser($u = $this->getUser());
						SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_UPDATE, $e, $u, $roles);
					}
					return true;
				}
			}
		}

		return false;
	}
}