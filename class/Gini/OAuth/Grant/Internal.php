<?php

namespace Gini\OAuth\Grant;

// PHP 8.3: 此文件已废弃
// Internal grant 的逻辑已内联到 \Gini\OAuth\Authorization::_completeInternalGrant()
// 保留此文件仅为避免外部引用报错

/**
 * @deprecated 使用 \Gini\OAuth\Authorization::issueAccessToken($params, true) 代替
 */
class Internal
{
    protected $identifier = 'internal';
}
