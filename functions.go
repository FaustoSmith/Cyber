package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

func getCharCode(text string, delimiter string) {
	var result strings.Builder
	for _, temp := range text {
		code := int(temp)
		result.WriteString(strconv.Itoa(code)) //Itoa parse con base 10,en caso de necesitar una base diferente usar ParseInt
		result.WriteString(delimiter)
	}
	fmt.Println(result.String())
}

func fromCharCode(charCode string, delimiter string) {
	var result strings.Builder
	charList := strings.Split(charCode, delimiter)
	for _, char := range charList {
		code, err := strconv.Atoi(char)
		if err != nil {
			fmt.Println(err.Error())
		} else {
			result.WriteString(string(code))
		}
	}
	fmt.Println(result.String())
}

func stringToHex(text string, bytesPerLine int, delimiter string) {
	//result := hex.Dump([]byte(text))
	var result strings.Builder
	for _, char := range text {
		s := fmt.Sprintf("%x", char)
		result.WriteString(s)
		result.WriteString(delimiter)
	}
	if bytesPerLine == 0 {
		fmt.Println(result.String())
	} else {
		resultString := strings.Split(result.String(), delimiter)
		count := 0
		for index, value := range resultString {
			if index != len(resultString)-1 {
				if count >= int(math.Abs(float64(bytesPerLine))) {
					fmt.Println()
					fmt.Print(string(value) + delimiter)
					count = 1
				} else {
					fmt.Print(string(value) + delimiter)
					count++
				}
			}
		}
	}
}

func fromHex(text string, delimiter string) {
	var result strings.Builder
	list := strings.Split(text, delimiter)
	for _, value := range list {
		code, err := hex.DecodeString(value)
		if err != nil {
			fmt.Println("Error decodificando :" + err.Error())
		} else {
			result.WriteString(string(code))
		}
	}
	fmt.Print(result.String())
}

func toDecimal(text string, delimiter string) {
	var result strings.Builder
	for index, code := range text {
		value := int(code)
		result.WriteString(strconv.Itoa(value))
		if index != len(text)-1 {
			result.WriteString(delimiter)
		}
	}
	fmt.Println(result.String())
}

func fromDecimal(number string, delimiter string) {
	var result strings.Builder
	numberList := strings.Split(number, delimiter)
	for _, code := range numberList {
		value, err := strconv.Atoi(code)
		if err != nil {
			fmt.Printf("Error: %v decodificando caracter : %v \n", err.Error(), code)
		} else {
			result.WriteString(string(value))
		}
	}
	fmt.Println(result.String())
}

func toBinary(text string, delimiter string) {
	var result strings.Builder
	for _, value := range text {
		original := fmt.Sprintf("%b", value)
		amountCeros := 8 - len(original)
		for i := 0; i < amountCeros; i++ {
			result.WriteString("0")
		}
		result.WriteString(original)
		result.WriteString(delimiter)
	}
	fmt.Println(result.String())
}

func fromBinary(text string) {
	//Dividir la cadena en nytes de 8 bits
	binaryBytes := strings.Split(text, " ")

	//Crear slice para guardar los bytes convertidos
	byteValues := make([]byte, len(binaryBytes))

	for i, value := range binaryBytes {
		decimalValue, err := strconv.ParseInt(value, 2, 8)
		if err != nil {
			fmt.Println("Error: " + err.Error())
			return
		} else {
			byteValues[i] = byte(decimalValue)
		}
	}
	fmt.Println(string(byteValues))
}

func toOctal(text string, delimiter string) {
	var result strings.Builder
	for _, value := range text {
		result.WriteString(fmt.Sprintf("%o", value))
		result.WriteString(delimiter)
	}
	fmt.Println(result.String())
}

// func fromOctal(octal string, delimiter string) {
// 	numberList := strings.Split(octal, delimiter)
// 	characters:=make([]rune,len(numberList))
// 	for i, octalNumber:= range numberList {
// 		value, err := strconv.ParseInt(octalNumber, 8, 0)
// 		if err != nil {
// 			fmt.Printf("Error: %v decodificando caracter : %v \n", err.Error(), octalNumber)
// 		} else {
// 			characters[i]=rune(value)
// 		}
// 	}
// 	fmt.Println(characters)
// }

func toBase64(text string) {
	bytes := []byte(text)
	encoded := base64.StdEncoding.EncodeToString(bytes)
	fmt.Println(encoded)
}

func fromBase64(text string) {
	code, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		fmt.Printf("Error %v decodificando \n", err.Error())
	}
	fmt.Println(string(code))
}

func urlEncode(text string) {
	encoded := url.QueryEscape(text)
	fmt.Println(encoded)
}

func urlDecode(text string) {
	decoded, err := url.QueryUnescape(text)
	if err != nil {
		fmt.Printf("Error %v decoding: %v \n", err.Error(), text)
		return
	} else {
		fmt.Println(decoded)
	}
}

func decodeJwt(jwtString string, llave string) {
	//Parsear token
	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		// Verificar el método de firma para algoritmos HMAC
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("Método de firma no válido")
		}
		// Devolver la clave secreta utilizada para firmar el token
		return []byte(llave), nil
	})
	if err != nil {
		fmt.Println("Error al decodificar el token:", err)
		return
	}
	// Verificar si el token es válido
	if token.Valid {
		// Acceder a los claims (datos del usuario)
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			fmt.Println("Error al obtener los claims del token")
			return
		}
		// Imprimir información del usuario
		fmt.Println("ID de usuario:", claims["sub"])
		fmt.Println("Nombre de usuario:", claims["name"])
		fmt.Println("Tiempo de emisión:", claims["iat"])
	} else {
		fmt.Println("Token no valido")
	}
}

func unique(text string, delimiter string) {
	list := strings.Split(text, delimiter)
	resultMap := map[string]int{}
	for _, key := range list {
		value, present := resultMap[key]
		if present {
			resultMap[key] = value + 1
		} else {
			resultMap[key] = 1
		}
	}
	for k, v := range resultMap {
		fmt.Println(v, " ", k)
	}
}

func scapeString(text string, quote string, jsonCompatible bool, level string) {
	var result strings.Builder
	if strings.EqualFold(level, "everything") {
		for _, char := range text {
			result.WriteString(fmt.Sprintf("%U", char))
		}
		if jsonCompatible {
			fmt.Println(quote, result.String(), quote)
		} else {
			fmt.Println(result.String())
		}
	} else if strings.EqualFold(level, "special char") {
		scaped := strconv.QuoteToASCII(text)
		if jsonCompatible {
			fmt.Println(quote, scaped, quote)
		} else {
			fmt.Println(scaped)
		}
	}
}

func changeIpFormat(text, inputFormat, outputFormat string) {
	switch inputFormat {
	case "Dotted Decimal":
		{
			switch outputFormat {
			case "Dotted Decimal":
				{
					fmt.Println(text)
				}
			case "Decimal":
				{
					ip := net.ParseIP(text)
					if ip == nil {
						fmt.Printf("Invalid IP address: %v", text)
					} else {
						decimal := uint32(ip[12])<<24 | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15])
						fmt.Println(decimal)
					}

				}
			case "Octal": //Incompleto
				{
					ip := net.ParseIP(text)
					if ip == nil {
						fmt.Printf("Invalid IP address: %v", text)
					} else {
						octets := make([]string, len(ip))
						for i, b := range ip {
							octets[i] = strconv.FormatInt(int64(b), 8) // 8 indica que queremos la representación octal
						}
						// Unir los octetos con puntos y devolver el resultado
						result := strings.Join(octets, "")
						fmt.Println(result[9:])
					}
				}
			case "Hex":
				{
					ip := net.ParseIP(text)
					if ip == nil {
						fmt.Printf("Invalid IP address: %v", text)
					} else {
						hex := hex.EncodeToString(ip)
						fmt.Println(hex)

					}
				}
			}
		}
	}
}
