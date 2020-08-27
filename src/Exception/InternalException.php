<?php

namespace Skyline\Admin\Tool\Exception;


use Skyline\Security\Exception\SecurityException;

class InternalException extends SecurityException
{
	private $object;

	/**
	 * @return mixed
	 */
	public function getObject()
	{
		return $this->object;
	}

	/**
	 * @param mixed $object
	 * @return static
	 */
	public function setObject($object)
	{
		$this->object = $object;
		return $this;
	}
}