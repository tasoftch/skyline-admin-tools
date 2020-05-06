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


use Skyline\CMS\Security\Tool\Event\RoleEvent;
use Skyline\CMS\Security\Tool\Event\UpdateRoleEvent;
use Skyline\CMS\Security\UserSystem\Role;
use Skyline\CMS\Security\UserSystem\User;
use Skyline\Kernel\Service\SkylineServiceManager;
use Skyline\Security\Exception\SecurityException;
use TASoft\Util\ValueInjector;
use Throwable;

class UserRoleTool extends \Skyline\CMS\Security\Tool\UserRoleTool
{
	/**
	 * Adds a new role
	 *
	 * @param string $name
	 * @param Role|NULL $parent
	 * @param string|NULL $description
	 * @param int $options
	 * @return Role
	 * @throws SecurityException
	 */
	public function addRole(string $name, Role $parent = NULL, string $description = NULL, int $options = 0): Role {
		$name = strtoupper($name);

		$p = $parent ? $parent->getId() : 0;
		$rName = $parent ? ($parent->getRole() . ".$name") : $name;

		if($this->PDO->selectOne("SELECT id FROM SKY_ROLE WHERE parent = ? AND name = ? LIMIT 1", [$p, $name])["id"] ?? 0) {
			throw new SecurityException("Role %s already exists", 20, NULL, $rName);
		}

		// User can not add internal roles
		$options &= ~Role::OPTION_INTERNAL;
		$this->PDO->inject("INSERT INTO SKY_ROLE (name, description, parent, options) VALUES (?, ?, $p, $options)")->send([
			$name,
			$description ?: ""
		]);
		$id = $this->PDO->lastInsertId();
		$r = $this->cachedRoleNames[ $id ] = new Role([
			"role" => $rName,
			'id' => $id,
			'description' => $description ?: "",
			'options' => $options
		]);

		$this->roleIDNameMap[ $rName ] = $id;
		if($parent) {
			$this->parentRoles[ $id ] = $parent->getId();
			$this->childRoles[ $parent->getId() ][] = $id;
		}



		if(!$this->disableEvents) {
			$ev = new RoleEvent();
			$ev->setRole($r);
			SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_ROLE_ADD, $ev, $r);
		}


		return $r;
	}

	/**
	 * @param Role $role
	 * @param string $internalError
	 * @internal
	 */
	private function checkRoleIntegrity(Role $role, $internalError = "Role %s is internal and can not be changed") {
		$rid = $role->getId();
		$internal = Role::OPTION_INTERNAL;

		$result = $this->PDO->selectOne("SELECT CASE WHEN options & $internal > 0 THEN 1 ELSE 0 END AS internal FROM SKY_ROLE WHERE id = $rid")["internal"] ?? -1;
		if($result == -1)
			throw new SecurityException("No role %s in data base yet", 55, NULL, $role->getRole());
		if($result == 1)
			throw new SecurityException($internalError, 56, NULL, $role->getRole());
	}

	/**
	 * This method internally invalidates all users owning directly or by group assignment a given role
	 *
	 * @param int $roleID
	 */
	private function invalidateUserSession(int $roleID) {
		$o = User::OPTION_INVALIDATE_SESSION;

		$this->PDO->exec("UPDATE SKY_USER
				JOIN SKY_USER_ROLE ON user = id
				SET options = (options | $o)
				WHERE role = $roleID");
		$this->PDO->exec("UPDATE SKY_USER
				JOIN SKY_USER_GROUP ON user = id
				JOIN SKY_GROUP_ROLE SGR on SKY_USER_GROUP.groupid = SGR.groupid
				SET options = (options | $o)
				WHERE role = $roleID");
	}

	/**
	 * Removes a role from data base.
	 * Please note, that this action will also remove all relationships for the passed role.
	 * That means the following actions are done:
	 *
	 * - Trigger the remove role event (if enabled)
	 * - Removes assigned role from groups
	 * - Remove assigned role from users
	 * - Remove role
	 *
	 * @param Role $role
	 * @return bool
	 * @throws SecurityException
	 */
	public function removeRole(Role $role) {
		$this->checkRoleIntegrity($role, "Role %s is internal and can not be removed");

		if(!$this->disableEvents) {
			$ev = new RoleEvent();
			$ev->setRole($role);
			SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_ROLE_REMOVE, $ev, $role);
		}

		try {
			$this->PDO->transaction(function() use ($role) {
				$children = iterator_to_array( $this->yieldAllChildren($role) );
				$children[] = $role;

				foreach ($children as $r) {
					$rid = $r->getId();

					$this->PDO->exec("DELETE FROM SKY_GROUP_ROLE WHERE role = $rid");
					$this->PDO->exec("DELETE FROM SKY_USER_ROLE WHERE role = $rid");
					$this->PDO->exec("DELETE FROM SKY_ROLE WHERE id = $rid");

					$this->invalidateUserSession($rid);
				}
			});
		} catch (Throwable $exception) {
			trigger_error($exception->getMessage(), E_USER_WARNING);
			return false;
		}
		return true;
	}

	/**
	 * Updates the passed role to have new properties.
	 *
	 * @param Role $role
	 * @param string|NULL $newName          A new name if not NULL
	 * @param string|NULL $newDescription   A new description if not NULL
	 * @param int|NULL $newOptions          New options if not NULL
	 * @return bool
	 */
	public function updateRole(Role $role, string $newName = NULL, string $newDescription = NULL, int $newOptions = NULL) {
		$this->checkRoleIntegrity($role, 'Role %s is internal and can not be changed');

		if($newName) {
			$newName = strtoupper(
				$newName
			);

			$p = $this->parentRoles[ $role->getId() ] ?? 0;

			if($this->PDO->selectOne("SELECT id FROM SKY_ROLE WHERE parent = ? AND name = ? LIMIT 1", [$p, $newName])["id"] ?? 0) {
				$p = $this->getParent($role);
				throw new SecurityException("Role %s already exists", 20, NULL, $p ? ($p->getRole() . ".$newName") : $newName);
			}
		}

		if(NULL !== $newOptions) {
			$newOptions &= ~Role::OPTION_INTERNAL;
		}

		if(!$this->disableEvents) {
			$ev = new UpdateRoleEvent();
			$ev->setRole($role);
			$ev->setOptions($newOptions);
			$ev->setDescription($newDescription);
			$ev->setName($newName);

			SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_ROLE_UPDATE, $ev, $role);

			$newName = $ev->getName();
			$newOptions = $ev->getOptions();
			$newDescription = $ev->getDescription();
		}

		try {
			$PDO = $this->PDO;
			$rid = $role->getId();

			$this->PDO->transaction(function() use ($PDO, $newName, $newDescription, $newOptions, $rid) {
				if($newName)
					$PDO->inject("UPDATE SKY_ROLE SET name = ? WHERE id = $rid")->send([$newName]);
				if(NULL !== $newDescription)
					$PDO->inject("UPDATE SKY_ROLE SET description = ? WHERE id = $rid")->send([$newDescription]);
				if(NULL !== $newOptions)
					$PDO->inject("UPDATE SKY_ROLE SET options = ? WHERE id = $rid")->send([$newOptions]);
			});

			$vi = new ValueInjector($role, Role::class);
			$vi->description = $newDescription;
			$vi->options = $newOptions;

			if(NULL !== $newName) {
				$data = explode(".", $role->getRole());
				array_pop($data);
				$data[] = $newName;
				$newRole = implode(".", $data);

				unset($this->roleIDNameMap[ $role->getRole() ]);
				$this->roleIDNameMap[ $newRole ] = $role->getId();

				$vi->setObject($role, \Skyline\Security\Role\Role::class);
				$vi->role = $newRole;
			}

			return true;
		} catch (Throwable $exception) {
			trigger_error($exception->getMessage(), E_USER_WARNING);
			return false;
		}
	}

	/**
	 * Changes the parent of a role.
	 *
	 * @param Role $role
	 * @param Role|NULL $parent
	 * @return bool
	 */
	public function updateRoleParent(Role $role, Role $parent = NULL) {
		$this->checkRoleIntegrity($role, 'Role %s is internal and can not be changed');
		$p = $this->getParent($role);

		$rid = $role->getId();

		if($parent && ($p === NULL || $p->getId() != $parent->getId())) {
			if($parent->getOptions() & Role::OPTION_FINAL)
				throw new SecurityException("Role %s is final", 58, NULL, $parent->getRole());

			if(!$this->disableEvents) {
				$ev = new UpdateRoleEvent();
				$ev->setRole($role);
				$ev->setParentRole($parent);
				SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_ROLE_UPDATE, $ev);
			}

			$pid = $parent->getId();
			$this->PDO->exec("UPDATE SKY_ROLE SET parent = $pid WHERE id = $rid");
			$this->cachedRoleNames = $this->roleIDNameMap = $this->parentRoles = $this->childRoles = NULL;

			$children = iterator_to_array( $this->yieldAllChildren($role) );
			$children[] = $role;

			foreach ($children as $r) {
				$rid = $r->getId();
				$this->invalidateUserSession($rid);
			}

			return true;
		} elseif($p) {

			if(!$this->disableEvents) {
				$ev = new UpdateRoleEvent();
				$ev->setRole($role);
				$ev->setParentRole(NULL);
				SkylineServiceManager::getEventManager()->trigger(SKY_EVENT_USER_ROLE_UPDATE, $ev);
			}

			$this->PDO->exec("UPDATE SKY_ROLE SET parent = 0 WHERE id = $rid");
			$this->cachedRoleNames = $this->roleIDNameMap = $this->parentRoles = $this->childRoles = NULL;

			$children = iterator_to_array( $this->yieldAllChildren($role) );
			$children[] = $role;

			foreach ($children as $r) {
				$rid = $r->getId();
				$this->invalidateUserSession($rid);
			}
			return true;
		}

		return false;
	}
}