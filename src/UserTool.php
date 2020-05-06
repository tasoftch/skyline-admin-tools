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

use Skyline\CMS\Security\Authentication\AuthenticationServiceFactory;
use Skyline\CMS\Security\Tool\Event\UserEvent;
use Skyline\CMS\Security\Tool\PasswordResetTool;
use Skyline\CMS\Security\UserSystem\User;
use Skyline\Kernel\Service\SkylineServiceManager;
use Skyline\Security\Authentication\AuthenticationService;
use Skyline\Security\User\UserInterface;
use TASoft\Service\ServiceManager;

class UserTool extends \Skyline\CMS\Security\Tool\UserTool
{
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
	 * @param string $username
	 * @param string $plainCredential
	 * @param int|null $errorCode
	 * @return UserInterface|null
	 *
	 */
	public function createUser(string $username, string $plainCredential, int &$errorCode = NULL): ?UserInterface {
		/** @var PasswordResetTool $pwt */
		$pwt = ServiceManager::generalServiceManager()->get( PasswordResetTool::SERVICE_NAME );
		if(!$pwt)
			return NULL;

		$this->getPDO()->inject("INSERT INTO SKY_USER (username, credentials) VALUES (?, ?)")->send([
			$username,
			'#'
		]);
		if($user = $this->getUser( $username )) {
			if($pwt->updateUserPassword($user, $plainCredential, $errorCode)) {
				if(!$this->disableEvents) {
					$e = new UserEvent();
					$e->setUser($user);
					SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_ADD, $e, $user, $errorCode);
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
	 * Removes a user from the system
	 *
	 * @param UserInterface $user
	 * @throws \Throwable
	 */
	public function removeUser(UserInterface $user) {
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
	 * @return bool
	 * @throws \Throwable
	 */
	public function assignGroups(array $groups = NULL) {
		if($uid = $this->getUserID()) {
			$gt = ServiceManager::generalServiceManager()->get(\Skyline\CMS\Security\Tool\UserGroupTool::SERVICE_NAME);
			if($gt instanceof \Skyline\CMS\Security\Tool\UserGroupTool) {
				if($this->getPDO()->transaction(function() use ($uid, &$groups, $gt) {
					$this->getPDO()->exec("DELETE FROM SKY_USER_GROUP WHERE user = $uid");

					if($groups) {
						$insert = $this->getPDO()->inject("INSERT INTO SKY_USER_GROUP (user, groupid) VALUES ($uid, ?)");

						foreach($groups as &$group) {
							if($group = $gt->getGroup($group))
								$insert->send([$group->getId()]);
						}
					}

					$o = User::OPTION_INVALIDATE_SESSION;
					$this->getPDO()->exec("UPDATE SKY_USER SET options = (options | $o) WHERE id = $uid");
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
	 * @return bool
	 * @throws \Throwable
	 */
	public function assignRoles(array $roles = NULL) {
		if($uid = $this->getUserID()) {
			$gt = ServiceManager::generalServiceManager()->get(\Skyline\CMS\Security\Tool\UserRoleTool::SERVICE_NAME);
			if($gt instanceof \Skyline\CMS\Security\Tool\UserRoleTool) {
				if($this->getPDO()->transaction(function() use ($uid, &$roles, $gt) {
					$this->getPDO()->exec("DELETE FROM SKY_USER_ROLE WHERE user = $uid");

					if($roles) {
						$insert = $this->getPDO()->inject("INSERT INTO SKY_USER_ROLE (user, role) VALUES ($uid, ?)");

						foreach($roles as &$role) {
							if($role = $gt->getRole($role))
								$insert->send([$role->getId()]);
						}
					}

					$o = User::OPTION_INVALIDATE_SESSION;
					$this->getPDO()->exec("UPDATE SKY_USER SET options = (options | $o) WHERE id = $uid");
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