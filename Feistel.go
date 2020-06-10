package main

import (
	"fmt"
)

const (
	LOOP_NUM = 16
)

func main() {
	var key string = "ABCDEFGHIJKLMNOP"
	var data string = "Android将军->GeneralAndroid"

	fmt.Printf("加密之前的明文：%x\n", []byte(data))
	right, left, keys := FeistelEncrypt(data, key)

	Encrypt_result := append(right, left...)

	fmt.Printf("加密之后的密文以及最后一轮子秘钥：%x,%x\n", Encrypt_result, keys)

	Decrypt_result, D_key := FeistelDecrypt(right, left, generateKeys(key))

	fmt.Printf("解密之后的明文以及第一轮的子秘钥：%x,%x\n", Decrypt_result, D_key)

}

//generate keys
func generateKeys(key string) []byte {
	var byte_key = []byte(key)
	keys := []byte{}
	keys = byte_key
	return keys
}

//移位运算计算子秘钥 还存在很大的漏洞要修改
//加密
//func bitmove(temp []byte,distance int)[]byte{
//	var i int
//	result := make([]byte,len(temp))
//
//	for i=0;i<len(temp);i++{
//		if distance%len(temp) >= len(temp)/2{
//			result[i] = temp[i] >> 1
//		}else {
//			result[i] = temp[i] << 1
//		}
//	}
//	return result
//}

//解密
//func Dbitmove(temp []byte,distance int)[]byte{
//	var i int
//	result := make([]byte,len(temp))
//	for i=0;i<len(temp);i++{
//		if distance%len(temp) >= len(temp)/2{
//			result[i] = temp[i] << 1
//		}else {
//			result[i] = temp[i] >> 1
//		}
//	}
//	return result
//}

//right and ki function
func function(right []byte, key byte) []byte {
	outputBytes := []byte{}

	for _, right_byte := range right {
		outputBytes = append(outputBytes, getMod(right_byte, key))
	}

	return outputBytes
}

func getMod(right_byte, key_byte byte) byte {
	if right_byte == 0 {
		return key_byte
	}

	if key_byte == 0 {
		return right_byte
	}

	if right_byte >= key_byte {
		return right_byte % key_byte
	} else {
		return key_byte % right_byte
	}
}

//迭代计算的一轮计算过程
func applyFeistel(left, right []byte, key byte) ([]byte, []byte) {
	nextleft := right

	prepare_data := function(right, key)

	nextright := []byte{}

	nextright = Xor(left, prepare_data)

	return nextleft, nextright
}

//主要迭代加密过程，返回加密成功的密文和最后一轮所使用的子秘钥
func FeistelEncrypt(data, key string) ([]byte, []byte, byte) {
	byte_data := []byte(data)

	byte_data_len := len(byte_data)
	if byte_data_len%2 != 0 {
		byte_data = append(byte_data, byte(0))
	}
	byte_data_len_len := len(byte_data)
	midlen := int(byte_data_len_len / 2)

	left := byte_data[:midlen]
	right := byte_data[midlen:]
	keys := generateKeys(key)

	var i int

	for i = 0; i < LOOP_NUM; i++ {
		nextleft, nextright := applyFeistel(left, right, keys[i])
		left = nextleft
		right = nextright
		//fmt.Printf("第%d轮的子秘钥：%x\n",i+1,keys[i])

	}

	return right, left, keys[LOOP_NUM-1]

}

//xor
func Xor(a, b []byte) []byte {
	n := len(a)

	if len(b) < n {
		n = len(b)
	}
	dst := make([]byte, n)

	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	return dst[:]
}

//Decrypt

func FeistelDecrypt(right1, left1, keys []byte) ([]byte, byte) {
	var i int
	right := left1
	left := right1
	for i = LOOP_NUM - 1; i >= 0; i-- {
		nextleft, nextright := applyFeistel(left, right, keys[i])
		left = nextleft
		right = nextright
		//fmt.Printf("第%d轮的子秘钥：%x\n",i+1,keys[i])

	}

	return append(right, left...), keys[0]
}
