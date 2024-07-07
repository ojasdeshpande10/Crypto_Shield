
package main

import (
    "flag"
    "log"
	"net"
    // "io"
    "os"
    "crypto/aes"
    "golang.org/x/crypto/pbkdf2"
	"crypto/cipher"
    "crypto/rand"
    "crypto/sha1"
    "encoding/binary"
    // "fmt"
)

// Prepending length to the cipher text


func prependLength(byteSlice []byte) []byte {
	length := uint32(len(byteSlice))
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, length)
	return append(lengthBytes, byteSlice...)
}


func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
    if _, err := rand.Read(nonce); err != nil {
		log.Println("error in nonce generation")
        return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext:= aesgcm.Seal(nil, nonce, plaintext, nil)
    ciphertextWithNonce := append(nonce, ciphertext...)

	return ciphertextWithNonce, nil
}
func decrypt(ciphertextWithNonce, key []byte) ([]byte, error) {
    nonce := ciphertextWithNonce[:12]
	ciphertext := ciphertextWithNonce[12:]
    block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
        log.Println("error in creating new gcm block")
		return nil, err
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
        log.Println("error in Open [ %v   ]", err)
		return nil, err
	}
    //log.Println("length of plaintext is ", len(plaintext))
	return plaintext, nil
}



func startClientMode(destination, key string) {
    // Connect to the destination

    var salt []byte
    dk := pbkdf2.Key([]byte(key), salt, 4096, 32, sha1.New)
    logFile := "logfile_client.txt"
    logWriter, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("Failed to open log file: %v", err)
    }
    defer logWriter.Close()
    log.SetOutput(logWriter)
    destConn, err := net.Dial("tcp", destination)
    if err != nil {
        log.Fatalf("Failed to connect to destination [%s]: %v\n", destination, err)
    }
    defer destConn.Close()

    log.Printf("Connected to destination [%s] in client mode\n", destination)

    // // Copy data from stdin to the destination
    go func() {
        for {
            // Read data from os.Stdin
            inputData := make([]byte, 1024*64) // Adjust the buffer size as needed
            n, err := os.Stdin.Read(inputData)
            if err != nil {
                log.Printf("Error reading from stdin: %v\n", err)
                break
            }
            log.Println("[***CLIENT*****]Read these number of bytes from stdin is %d",n)
            // Send the data to the destination if any data is read
            if n > 0 {
                encryptedData, err := encrypt(inputData[:n], dk)
                encrypt_channel := prependLength(encryptedData)
                // log.Println("[***CLIENT*****]Length of encrypted text with prepended ",len(encrypt_channel))
                // log.Println("[***CLIENT*****]Length of encrypted text without prepended ",len(encryptedData))
                _, err = destConn.Write(encrypt_channel)
                if err != nil {
                    log.Printf("Error sending data to destination: %v\n", err)
                    break
                }
            }
            log.Println("Written to destination")
        }
    }()


    for {
        // Read data from os.Stdin
        inputData_len := make([]byte, 4) // Adjust the buffer size as needed
        n, err := destConn.Read(inputData_len)
        if err != nil {
            log.Printf("Error reading from stdin: %v\n", err)
            break
        }
        log.Println("[***CLIENT*****]Read these number of bytes from destination is %d",n)

        // Send the data to the destination if any data is read

        if n > 0 {
            length := binary.BigEndian.Uint32(inputData_len)
            input_byte := make([]byte, 1)
            input_total := make([]byte, length)
            var cnt uint32 = 0
            for {
                n, err := destConn.Read(input_byte)
                if err!=nil {
                    log.Println("the error in the reading one byte is %v", err)
                }
                if n==1 {
                    input_total[cnt] = input_byte[0]
                    cnt++
                    if cnt == length {
                        break
                    }   
                }  
            }
            // log.Println("[***CLIENT*****]Length of ciphertext ",length)
            decrypted_data, err := decrypt(input_total[:length], dk)
            // log.Println("[***CLIENT*****]length of decrypted_data ",len(decrypted_data))
            _, err = os.Stdout.Write(decrypted_data)
            if err != nil {
                log.Printf("Error sending data to destination: %v\n", err)
                break
            }
        }
        log.Println("Written to output")
    }
}

func startReverseProxyMode(listenPort, destination, key string) {
    // Listen on the specified port
    var salt []byte
    dk := pbkdf2.Key([]byte(key), salt, 4096, 32, sha1.New)
    logFile := "logfile_server.txt"
    logWriter, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatalf("Failed to open log file: %v", err)
    }
    defer logWriter.Close()
    log.SetOutput(logWriter)
    listener, err := net.Listen("tcp", ":"+listenPort)
    if err != nil {
        log.Fatalf("Failed to listen on port %s: %v\n", listenPort, err)
    }
    defer listener.Close()
    log.Printf("Reverse proxy listening on port %s, forwarding to %s\n", listenPort, destination)
    // Accept incoming connections
    for {
        clientConn, err := listener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v\n", err)
            continue
        }
		log.Println("Got a connection from the client")
        go handleConnection(clientConn, destination, dk)
    }
}
func handleConnection(clientConn net.Conn, destination string, key []byte) {
    // Dial the destination
    destConn, err := net.Dial("tcp", destination)
    if err != nil {
        log.Printf("Unable to connect to destination [%s]: %v\n", destination, err)
        return
    }
    defer destConn.Close()
    go func() {
        for {
            inputData_len := make([]byte, 4) // Adjust the buffer size as needed
            n, err := clientConn.Read(inputData_len)
            if err != nil {
                log.Printf("[******SERVER****]Error reading from clientConn: %v\n", err)
                break
            }
            // Send the data to the destination if any data is read
            if n > 0 {
                length := binary.BigEndian.Uint32(inputData_len)
                input_byte := make([]byte, 1)
                input_total := make([]byte, length)
                var cnt uint32 = 0
                log.Println("reading byte byte from proxy>> of length", length)
                for {
                    n, err := clientConn.Read(input_byte)
                    if err!=nil {
                        log.Println("the error in the reading one byte is %v", err)
                        break
                    }
                    if n==1 {
                        input_total[cnt] = input_byte[0]
                        cnt++
                        if cnt == length {
                            break
                        }   
                    }  
                }
                log.Println("reading DONE byte byte from proxy>> of length: ",length)
                decrypted_data, err := decrypt(input_total[:length], key)
                _, err = destConn.Write(decrypted_data)
                if err != nil {
                    log.Printf("[******SERVER****]Error sending data to destination: %v\n", err)
                    break
                }
            }
            log.Println("Written to destination")
        }
    }()


    for {
        // Read data from destination
        inputData := make([]byte, 1024*64) 
        n, err := destConn.Read(inputData)
        if err != nil {
            log.Printf("Error reading from destination: %v\n", err)
            break
        }
        // Send the data to the destination if any data is read
        log.Println("[***CLIENT*****]Read these number of bytes from destin is %d",n)
        if n > 0 {
            encryptedData, err := encrypt(inputData[:n], key)
            encrypt_channel := prependLength(encryptedData)
            _, err = clientConn.Write(encrypt_channel)
            if err != nil {
                log.Printf("Error sending data to client: %v\n", err)
                break
            }
        }
        log.Println("Written to client conn")

    }

}


func main() {
    listenPort := flag.String("l", "", "Port to listen on (reverse-proxy mode)")
    destination := flag.String("d", "", "Destination address (client mode or reverse-proxy mode)")
    keyfile := flag.String("k", "", "Key for encryption")
    flag.Parse()
    content, err := os.ReadFile(*keyfile)
    if err != nil {
        log.Fatal(err)
    }
    key := string(content)
    log.Println(key)
    if *listenPort != "" && *destination != "" {
        // If both listenPort and destination are specified, start in reverse-proxy mode
        log.Println("the destination port is ", *listenPort)
		startReverseProxyMode(*listenPort, *destination,key)
    } else if *destination != "" {
        // If only destination is specified, start in client mode
		startClientMode(*destination, key)
    } else {
        log.Println("You must specify a destination. In reverse-proxy mode, you must also specify a listen port.")
    }
}