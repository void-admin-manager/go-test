package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

type UserTable struct {
	UID             int
	UserName        sql.NullString
	ChineseName     sql.NullString
	Information     sql.NullString
	Photo           sql.NullString
	Address         sql.NullString
	Account_balance sql.NullFloat64
	EXP             sql.NullFloat64
	Level           sql.NullFloat64
}

type Sql_connect struct {
	DbUser       string
	DbPassword   string
	DbServername string
	DbProt       string
	DbName       string
}

func encryptAES(plaintext []byte, key []byte) ([]byte, error) {
	//创建一个AES加密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//填充明文以满足AES块大小的要求
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize

	//重新分配比特块
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	//拼接
	plaintext = append(plaintext, padtext...)

	//初始化加密器
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	//加密明文
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func decryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	//创建一个aes块解密器
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//分离初始化向量
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	//检查密文长度
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	//解密密文
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	//去除填充
	padding := int(ciphertext[len(ciphertext)-1])
	if padding < 1 || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	ciphertext = ciphertext[:len(ciphertext)-padding]

	return ciphertext, nil
}

// RSA加密带标签
func EncryptWithPublicKey(plaintext string, publickey *rsa.PublicKey, label []byte) ([]byte, error) {
	//哈希，随机数，公钥，明文转字节切片，标签
	ciphertxet, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publickey, []byte(plaintext), label)
	if err != nil {
		return nil, err
	}
	return ciphertxet, nil
}

// RSA解密带标签
func DecryptWithPrivateKey(ciphertext []byte, privateKey *rsa.PrivateKey, label []byte) (string, error) {
	//哈希，随机数，私钥，密文字节切片，标签（必须要与加密的标签一致）
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, label)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// 用户密码加密(密文，公钥PEM，私钥PEM，错误)
func UserPassword_encryption(pwd string) (string, string, string, error) {
	//创建密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	publicKey := &privateKey.PublicKey

	//转换成PEM块准备存入数据库
	privateKeyPEM := &pem.Block{
		Type:  "Private Key PEM",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	publicKeyPEM := &pem.Block{
		Type:  "Public Key PEM",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}

	ciphertext, err := EncryptWithPublicKey(pwd, publicKey, []byte("nilaodou"))
	if err != nil {
		return "", "", "", err
	}

	// 将密文编码为Base64字符串
	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)

	// 将PEM块编码为字符串
	encodedPublicKeyPEM := string(pem.EncodeToMemory(publicKeyPEM))
	encodedPrivateKeyPEM := string(pem.EncodeToMemory(privateKeyPEM))

	return encodedCiphertext, encodedPublicKeyPEM, encodedPrivateKeyPEM, nil
}

// 密码哈希加盐(字节流)
func PWDHashSalt(pwd string) ([]byte, error) {
	//将密码转换成字节
	password := []byte(pwd)

	//生成随机数
	salt, err := HashRand()
	if err != nil {
		log.Fatal(err)
	}

	//将密码和盐值拼接
	saltedPassword := append(password, salt...)

	//使用哈希256
	hash := sha256.Sum256(saltedPassword)

	return hash[:], nil
}

// 密码哈希加盐(字符串)
func PWDHashSaltString(pwd string) {

}

// 已有随机数的哈希加盐
func SaltedPWDHash(PWD, Salt string) (string, error) {
	//转换成字节流
	password := []byte(PWD)
	SalValue := []byte(Salt)

	//拼接
	saltedPassword := append(password, SalValue...)

	//使用哈希256
	hash := sha256.Sum256(saltedPassword)

	hashed := hash[:]

	return hex.EncodeToString(hashed), nil
}

// 哈希随机数(字节流)
func HashRand() ([]byte, error) {
	//初始化盐
	//采用最大盐值填充
	salt := make([]byte, 32)
	//为盐赋值
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}
	//返回盐值
	return salt, nil
}

// 哈希随机数(字符串)
func HashRandString() (string, error) {
	//初始化盐
	//采用最大盐值填充
	salt := make([]byte, 32)
	//为盐赋值
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// 文件哈希验证
func FileRead(Path string) []byte {
	fileByte, err := os.ReadFile(Path)
	if err != nil {
		log.Fatal(err)
	}
	//使用哈希
	fileHash := sha256.Sum256(fileByte)
	//拼接哈希字节碎片
	fileHashed := fileHash[:]
	return fileHashed
}

// 文件哈希验证(string)
func FileHashString(Path string) string {
	fileByte, err := os.ReadFile(Path)
	if err != nil {
		log.Fatal(err)
	}
	//使用哈希
	fileHash := sha256.Sum256(fileByte)
	// 拼接哈希字节碎片
	fileHashed := fileHash[:]
	//转换成字符串
	return hex.EncodeToString(fileHashed)
}

func get_result(tableName string, connect_args Sql_connect) []byte {
	var b []byte
	db, err := connect_mysql(connect_args)
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	query := fmt.Sprintf("SELECT * FROM %s", tableName)
	rows, err := db.Query(query)
	if err != nil {
		log.Fatal(err)
		return []byte(err.Error())
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		log.Fatal(err)
		return []byte(err.Error())
	}

	values := make([]interface{}, len(columns))
	for i := range values {
		values[i] = new(interface{})
	}

	for rows.Next() {
		err := rows.Scan(values...)
		if err != nil {
			fmt.Println(err)
			return []byte(err.Error())
		}

		rowMap := make(map[string]interface{})

		for i, value := range values {
			var v interface{}
			b, ok := (*value.(*interface{})).([]byte)
			if ok {
				v = string(b)
			} else {
				v = *value.(*interface{})
			}
			rowMap[columns[i]] = v
		}

		jsonData, err := json.Marshal(rowMap)
		if err != nil {
			fmt.Println(err)
			return []byte(err.Error())
		}

		b = append(b, jsonData...)
	}

	return b
}

func connect_mysql(connect_args Sql_connect) (*sql.DB, error) {
	conn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", connect_args.DbUser, connect_args.DbPassword, connect_args.DbServername, connect_args.DbProt, connect_args.DbName)

	db, err := sql.Open("mysql", conn)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return "NULL"
}

func NullFloat64ToFloat64(val sql.NullFloat64) float64 {
	if val.Valid {
		return float64(val.Float64)
	}
	return 0
}

func getVideoDuration(inputFile string) (int, error) {
	cmd := exec.Command("ffprobe", "-v", "error", "-show_entries",
		"format=duration", "-of", "default=noprint_wrappers=1:nokey=1", inputFile)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("ffprobe failed: %w\nOutput: %s", err, string(output))
	}

	durationStr := strings.TrimSpace(string(output))
	duration, err := strconv.ParseFloat(durationStr, 64)
	if err != nil {
		return 0, fmt.Errorf("parse duration failed: %w", err)
	}

	return int(duration), nil
}

func generateHLS(inputFile, outputDir, outputPrefix string) error {
	duration, err := getVideoDuration(inputFile)
	if err != nil {
		return err
	}

	segmentTime := 10
	switch {
	case duration > 1200:
		segmentTime = 60
	case duration < 10:
		segmentTime = duration
	}

	m3u8File := filepath.Join(outputDir, "playlist.m3u8")
	tsPattern := filepath.Join(outputDir, outputPrefix+"%03d.ts")

	cmd := exec.Command("ffmpeg",
		"-i", inputFile,
		"-c", "copy",
		"-map", "0",
		"-f", "segment",
		"-segment_time", strconv.Itoa(segmentTime),
		"-segment_format", "mpegts",
		"-segment_list", m3u8File,
		"-reset_timestamps", "1",
		tsPattern,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("FFmpeg HLS failed: %w", err)
	}

	log.Printf("HLS切片完成: %d秒视频, %d秒分段\n", duration, segmentTime)
	return nil
}

func generateDASH(inputFile, outputDir, outputPrefix string) error {
	duration, err := getVideoDuration(inputFile)
	if err != nil {
		return err
	}

	// 动态分段策略
	segmentDuration := 6
	switch {
	case duration > 600:
		segmentDuration = 10
	case duration < 6:
		segmentDuration = duration
	}

	// 生成MPD和分段文件
	mpdFile := filepath.Join(outputDir, outputPrefix+".mpd")

	cmd := exec.Command("ffmpeg",
		"-i", inputFile,
		"-c", "copy",
		"-f", "dash",
		"-seg_duration", strconv.Itoa(segmentDuration),
		"-dash_segment_type", "mp4",
		"-adaptation_sets", "id=0,streams=v id=1,streams=a",
		"-window_size", "100",
		"-remove_at_exit", "0",
		mpdFile,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("FFmpeg DASH failed: %w", err)
	}

	log.Printf("DASH切片完成: %d秒视频, %d秒分段\n", duration, segmentDuration)
	return nil
}

// 可以自定义扩展
func byteArraySplicing(byteArray []byte, datalength int) ([]byte, error) {
	if datalength <= 0 || datalength > 8 {
		return nil, fmt.Errorf("数据长度错误，请输入1到8之间的数据长度")
	}

	var splicingArray []byte //创建一个空的字节数组
	currentByte := byte(0)   //初始化操作字节
	currentBit := 0          // 当前已经填充的位数

	//获取每个切片的数据
	for _, b := range byteArray {
		//可操作空间
		remainingBits := 8 - currentBit
		//如果可操作空间大于比特长度
		if remainingBits >= datalength {
			// 足够空间在当前字节中存储数据
			// b位移到相应位置
			b = b << (8 - currentBit - datalength) //一个字节的长度 - 已经填充的长度 - 比特数据自身的长度
			fmt.Println("当前的B值：", b)
			//掩码
			mask := (1 << (datalength + (8 - currentBit - datalength))) - 1
			//&掩码确保只有这些位的数据
			dataToAdd := b & byte(mask)
			//使用|拼接
			currentByte = currentByte | dataToAdd
			fmt.Println("当前字节值：", currentByte)
			//更新已填充位数
			currentBit += datalength
			fmt.Println("当前已填充数据长度", currentBit)
			//如果填充数据等于一字节
			if currentBit == 8 {
				//写入新的字节数组
				splicingArray = append(splicingArray, currentByte)
				//初始化需要操作的字节
				currentByte = 0
				//初始化比特位
				currentBit = 0
			}
		} else {
			// 剩余需要填充的位
			bitsToFillCurrentByte := remainingBits
			//掩码
			mask := (1 << bitsToFillCurrentByte) - 1
			//右移bitsToFillCurrentByte位数以确保拼接上一个未完成字节的空白位
			dataToAdd := (b >> (datalength - bitsToFillCurrentByte)) & byte(mask)
			//上一个未完成的字节拼接,移开相对应的位让dataToAdd拼接
			fmt.Println("当前字节值：", currentByte)
			currentByte = currentByte | dataToAdd
			fmt.Println("已完成的字节值：", currentByte)
			//拼接完成，加入字节数组
			splicingArray = append(splicingArray, currentByte)

			fmt.Println("当前b值：", b)
			currentByte = b << ((8 - datalength) + bitsToFillCurrentByte)
			fmt.Println("已填充完成的下一个字节初始值：", currentByte)
			//更新比特位
			currentBit = datalength - bitsToFillCurrentByte //数据长度减去填充位
		}
	}

	//最后一个bit(不满足一字节的时候拼接在末尾)
	if currentBit > 0 {
		splicingArray = append(splicingArray, currentByte)
	}

	return splicingArray, nil
}

// 可以扩展为多维数组，理论上可以实现计算到资源耗尽
// 太乱了不想重构，想到什么写什么，测试过可以用(PS：代码很傻逼，看得累的可以自己重构一下-_-!!!)
func Int_To_String_Jion(divisor interface{}, dividend interface{}) {
	//输入检测
	switch divisor.(type) {
	case int:
		break
	case uint:
		break
	case float32:
		break
	case float64:
		break

	default:
		err := "divisor参数请输入数字"
		fmt.Println(err)
		return
	}

	switch dividend.(type) {
	case int:
		break
	case uint:
		break
	case float32:
		break
	case float64:
		break

	default:
		err := "dividend参数请输入数字"
		fmt.Println(err)
		return
	}

	//初始化第一个参数长度
	divisor_len := 0
	//初始化第二个参数长度
	dividend_len := 0
	//初始化乘积倍率
	Product := 1
	//初始化最大长度
	max_len := 10
	//初始化余
	remainder := 0
	//初始化运算计数器
	calculation_counter := 0
	//初始化最大运算次数
	calculation_Max := 32

	quotient := 0

	//初始化结果
	result_string := ""

	//进位计数器
	carry_counter := 0

	if len(fmt.Sprintf("%v", divisor)) > max_len || len(fmt.Sprintf("%v", dividend)) > max_len {
		err := "超过最大长度限制"
		fmt.Println(err)
		return
	}

	// 取小数点后的数位长度
	if reflect.TypeOf(divisor).String() == "float32" || reflect.TypeOf(divisor).String() == "float64" {
		divisor_str := fmt.Sprintf("%v", divisor)
		parts := strings.Split(divisor_str, ".")
		if len(parts) == 1 {
			return
		}
		divisor_len = len(parts[1])
		// fmt.Println(divisor_len)
	}

	if reflect.TypeOf(dividend).String() == "float32" || reflect.TypeOf(dividend).String() == "float64" {
		dividend_str := fmt.Sprintf("%v", dividend)
		parts := strings.Split(dividend_str, ".")
		if len(parts) == 1 {
			return
		}
		dividend_len = len(parts[1])
		// fmt.Println(dividend_len)
	}

	// 获取最大长度的小数点数位（如果没有返回0）
	Product = int(math.Max(float64(divisor_len), float64(dividend_len)))
	// fmt.Println(Product)

	//整数计算
	if Product == 0 {
		//先计算整除部分
		remainder = division(divisor.(int), dividend.(int))
		fmt.Println("余数为：", remainder)
		fmt.Println("除数为：", divisor)
		fmt.Println("被除数为：", dividend)

		//累加计数器
		calculation_counter++

		//能被整除
		if remainder == 0 {
			quotient = dividend.(int) / divisor.(int)
			result_string = fmt.Sprintf("%d", quotient)
			fmt.Println("除法结果为:", result_string)
			return
		}

		//不能被整除，开始循环
		if remainder != 0 {
			// 计算一边整除部分
			quotient = (dividend.(int) - remainder) / divisor.(int)
			// 拼接入result_string
			result_string = fmt.Sprintf("%d", quotient)
			//先添加小数符号，以免在循环里反复添加
			result_string = result_string + "."
			// fmt.Println("小数点测试", result_string)

			//开始循环计算小数部分
			for i := 0; i < calculation_Max; i++ {
				//进入循环的余数
				fmt.Println("进入循环的余数为：", remainder)
				//进位，查看余数进一位是否大于除数
				carry_counter = compare_sizes(remainder, divisor.(int), 0)
				fmt.Println("需要进位", carry_counter)

				//放大余数
				// remainder = remainder * (carry_counter * 10)
				multiple_str := fmt.Sprintf("1%s", strings.Repeat("0", carry_counter))
				multiple, err := strconv.Atoi(multiple_str)
				if err != nil {
					fmt.Println(err)
				}
				remainder = remainder * multiple

				fmt.Println("放大后的余数为：", remainder)

				if carry_counter <= 1 {
					// 将余数赋值并设为新的被除数
					new_dividend := remainder
					fmt.Println("新的被除数为：", new_dividend)

					//更新余数
					remainder = new_dividend % divisor.(int)
					fmt.Println("执行运算后的余数为：", remainder)
					if remainder != 0 {
						//更新商
						quotient = (new_dividend - remainder) / divisor.(int)

						//更新字符串
						result_string = result_string + fmt.Sprintf("%d", quotient)
						fmt.Println(result_string)

						//归0
						carry_counter = 0
						fmt.Println("归零后的余数为：", remainder)
					} else {
						//更新商
						quotient = (new_dividend - remainder) / divisor.(int)

						//更新字符串
						result_string = result_string + fmt.Sprintf("%d", quotient)
						fmt.Println(result_string)

						//归0
						carry_counter = 0
						return
					}
				}

				if carry_counter > 1 {
					fmt.Println("进位大于1的函数开始执行")
					// 检测余数
					fmt.Println("进位大于1的函数时的余数为：", remainder)
					// 将余数赋值并设为新的被除数
					new_dividend := remainder
					// 更新余数
					remainder = new_dividend % divisor.(int)
					//如果余数不等于0
					if remainder != 0 {
						//更新商
						quotient = (new_dividend - remainder) / divisor.(int)

						//跟新字符串
						result_string = result_string + fmt.Sprintf("%s", strings.Repeat("0", carry_counter-1)) + fmt.Sprintf("%d", quotient)
						fmt.Println(result_string)

						//归0
						carry_counter = 0
					} else {
						//更新商
						quotient = (new_dividend - remainder) / divisor.(int)

						//跟新字符串
						result_string = result_string + fmt.Sprintf("%s", strings.Repeat("0", carry_counter-1)) + fmt.Sprintf("%d", quotient)
						fmt.Println(result_string)

						//归0
						carry_counter = 0
						return
					}
				}
			}
		}
	}

	if Product > 0 {
		//先计算进位
		multiple_str := fmt.Sprintf("1%s", strings.Repeat("0", Product))
		multiple, err := strconv.ParseFloat(multiple_str, 32)
		if err != nil {
			fmt.Println(err)
		}
		divisor = divisor.(float64) * multiple
		divisor = int(math.Floor(divisor.(float64)))
		dividend = dividend.(float64) * multiple
		dividend = int(math.Floor(dividend.(float64)))

		//先计算整除部分
		remainder = division(divisor.(int), dividend.(int))

		//累加计数器
		calculation_counter++

		//能被整除
		if remainder == 0 {
			quotient = dividend.(int) / divisor.(int)
			result_string = fmt.Sprintf("%d", quotient)
			fmt.Println("除法结果为:", result_string)
			return
		}

		//不能被整除，开始循环
		if remainder != 0 {
			// 计算一边整除部分
			quotient = (dividend.(int) - remainder) / divisor.(int)
			// 拼接入result_string
			result_string = fmt.Sprintf("%d", quotient)
			//先添加小数符号，以免在循环里反复添加
			result_string = result_string + "."
			// fmt.Println("小数点测试", result_string)

			//开始循环计算小数部分
			for i := 0; i < calculation_Max; i++ {
				//进入循环的余数
				fmt.Println("进入循环的余数为：", remainder)
				//进位，查看余数进一位是否大于除数
				carry_counter = compare_sizes(remainder, divisor.(int), 0)
				fmt.Println("需要进位", carry_counter)

				//放大余数
				// remainder = remainder * (carry_counter * 10)
				multiple_str := fmt.Sprintf("1%s", strings.Repeat("0", carry_counter))
				multiple, err := strconv.Atoi(multiple_str)
				if err != nil {
					fmt.Println(err)
				}
				remainder = remainder * multiple

				fmt.Println("放大后的余数为：", remainder)

				if carry_counter <= 1 {
					// 将余数赋值并设为新的被除数
					new_dividend := remainder
					fmt.Println("新的被除数为：", new_dividend)

					//更新余数
					remainder = new_dividend % divisor.(int)
					fmt.Println("执行运算后的余数为：", remainder)
					if remainder != 0 {
						//更新商
						quotient = (new_dividend - remainder) / divisor.(int)

						//更新字符串
						result_string = result_string + fmt.Sprintf("%d", quotient)
						fmt.Println(result_string)

						//归0
						carry_counter = 0
						fmt.Println("归零后的余数为：", remainder)
					} else {
						//更新商
						quotient = (new_dividend - remainder) / divisor.(int)

						//更新字符串
						result_string = result_string + fmt.Sprintf("%d", quotient)
						fmt.Println(result_string)

						//归0
						carry_counter = 0
						return
					}
				}

				if carry_counter > 1 {
					fmt.Println("进位大于1的函数开始执行")
					// 检测余数
					fmt.Println("进位大于1的函数时的余数为：", remainder)
					// 将余数赋值并设为新的被除数
					new_dividend := remainder
					// 更新余数
					remainder = new_dividend % divisor.(int)
					//如果余数不等于0
					if remainder != 0 {
						//更新商
						quotient = (new_dividend - remainder) / divisor.(int)

						//跟新字符串
						result_string = result_string + fmt.Sprintf("%s", strings.Repeat("0", carry_counter-1)) + fmt.Sprintf("%d", quotient)
						fmt.Println(result_string)

						//归0
						carry_counter = 0
					} else {
						//更新商
						quotient = (new_dividend - remainder) / divisor.(int)

						//跟新字符串
						result_string = result_string + fmt.Sprintf("%s", strings.Repeat("0", carry_counter-1)) + fmt.Sprintf("%d", quotient)
						fmt.Println(result_string)

						//归0
						carry_counter = 0
						return
					}
				}
			}
		}
	}
}

func division(divisor int, dividend int) int {
	remainder := dividend % divisor
	return remainder
}

// 进位
func compare_sizes(remainder int, divisor int, carry_counter int) int {
	if remainder < divisor {
		remainder *= 10
		carry_counter++
		return compare_sizes(remainder, divisor, carry_counter)
	} else {
		return carry_counter
	}
}

func main() {

}
