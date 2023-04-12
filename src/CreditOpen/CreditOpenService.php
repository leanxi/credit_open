<?php

namespace CreditOpen;

class CreditOpenService {


    private $customerId = '';
    private $aesKey = '';

    protected $url = 'https://creditopen.wlanbanlv.com';

    /**
     * 初始化
     * @param $customerId int 客户ID
     * @param $aesKey string 秘钥
     * @param false $isDevelop 是否测试环境，true为测试环境，false为生产环境
     */
    public function __construct ($customerId, $aesKey, $isDevelop = false) {
        $this->customerId = $customerId;
        $this->aesKey = $aesKey;
        if ($isDevelop) {
            $this->url = 'https://creditopen.zonelian.com';
        } else {
            $this->url = 'https://creditopen.wlanbanlv.com';
        }
    }

    /**
     * 获取申卡链接
     * @param array $data
     * @param string $serialNumber 业务流水号
     * @param string $userNo 用户ID
     * @throws \Exception
     */
    public function getApplyUrl($uniqueNo, $serialNumber, $data = [], $userNo = '')
    {

        $info = [
            'order_no' => $serialNumber,
            'user_no' => $userNo,

            // 以下字段为脱敏产品必传
            'mobile'    => isset($data['mobile']) ?: '',// 申卡用户手机号（明文）
            'name'      => isset($data['name']) ?: '', // 申卡用户姓名（明文）
            'id_number' => isset($data['id_card']) ?: '',  //身份证号码 （明文）
        ];
        $param = [
            'customer_id'   => $this->customerId,
            'unique_no'     => $uniqueNo,
            'coopinfo'      => $this->_newEncrypt(json_encode($info, JSON_UNESCAPED_UNICODE), $this->aesKey),
        ];
        // extra字段会原样返回
        if(!empty($data['extra'])){
            $param['extra'] = $data['extra'];
        }
        return $this->url . '/promotion?'.http_build_query($param);

    }

    /**
     * 加密
     * @param $str
     * @param $aesKey
     * @return string
     * @throws \Exception
     */
    private function _newEncrypt($str, $aesKey)
    {
        $str = openssl_encrypt($str, 'aes-128-ecb', $aesKey, OPENSSL_RAW_DATA, '');
        $error = openssl_error_string();
        if($error) {
            throw new \Exception('加密错误');
        }
        $returnRul = '';
        for ($i=0;$i<strlen($str);$i++) {
            $hex = bin2hex($str[$i]);
            if(strlen($hex) == 1) {
                $hex = '0' . $hex;
            }
            $returnRul = $returnRul.strtoupper($hex);
        }
        return $returnRul;
    }

    /**
     * 数据解密
     * @param $data
     * @return mixed
     * @throws \Exception
     */
    public function dataDecrypt($data) {
        try {
            $args = base64_decode(strtr($data, '-_,', '+/='));
            $args = json_decode(hex2bin($args), true);
        } catch (\Exception $e) {
            throw new \Exception('解析错误');
        }
        if (!isset($args['token'])) {
            throw new \Exception('解析错误');
        }
        $token = $args['token'];
        unset($args['token']);
        ksort($args);
        $signStr = '';
        foreach ($args as $k => $v) {
            if ($v || is_numeric($v)) {
                if (is_array($v)) {
                    $v = json_encode(array_map('strval', $v));
                }
                $signStr .= $k.$v;
            }
        }
        $newToken = strtoupper(md5(md5($signStr).$this->aesKey));
        if ($newToken != $token) {
            throw new \Exception('token校验失败');
        }
        return $args;
    }

}