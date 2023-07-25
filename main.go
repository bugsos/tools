package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func main() {
	inputFilePath := flag.String("in", "", "输入文件路径")
	password := flag.String("pwd", "", "密码")
	operation := flag.String("op", "", "操作类型（encrypt 或 decrypt）")
	outputFilePath := flag.String("out", "", "输出文件路径")

	flag.Parse()

	if *inputFilePath == "" || *password == "" || *operation == "" || *outputFilePath == "" {
		flag.Usage()
		os.Exit(1)
	}

	switch (*operation)[0] {
	case 'e':
		err := encryptFile(*inputFilePath, *outputFilePath, *password)
		if err != nil {
			fmt.Println("加密文件失败:", err)
			os.Exit(1)
		}
		fmt.Println("文件加密成功")
	case 'd':
		err := decryptFile(*inputFilePath, *outputFilePath, *password)
		if err != nil {
			fmt.Println("解密文件失败:", err)
			os.Exit(1)
		}
		fmt.Println("文件解密成功")
	default:
		fmt.Println("未知操作类型:", *operation)
		os.Exit(1)
	}
}

func encryptFile(inputFilePath, outputFilePath, password string) error {
	inputData, err := ioutil.ReadFile(inputFilePath)
	if err != nil {
		return err
	}

	encryptedData, err := encrypt(inputData, password)
	if err != nil {
		return err
	}

	return os.WriteFile(outputFilePath, encryptedData, 0644)
}

func decryptFile(inputFilePath, outputFilePath, password string) error {
	inputData, err := os.ReadFile(inputFilePath)
	if err != nil {
		return err
	}

	decryptedData, err := decrypt(inputData, password)
	if err != nil {
		return err
	}

	return os.WriteFile(outputFilePath, decryptedData, 0644)
}

func encrypt(data []byte, password string) ([]byte, error) {
	key := createKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encryptedData := make([]byte, aes.BlockSize+len(data))
	iv := encryptedData[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encryptedData[aes.BlockSize:], data)

	return encryptedData, nil
}

func decrypt(data []byte, password string) ([]byte, error) {
	key := createKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("数据太短")
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

func createKey(password string) []byte {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hash.Sum(nil)
}
