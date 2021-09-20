/*
Copyright © 2021 WONG JIUN CHENG <lolz1999@hotmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jiuncheng/passec/tools"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/pbkdf2"
)

var salt string = "y$B&E)H@McQfTjWnZr4u7w!z%C*F-JaNdRgUkXp2s5v8y/A?D(G+KbPeShVmYq3t6w9z$C&E)H@McQfTjWnZr4u7x!A%D*G-JaNdRgUkXp2s5v8y/B?E(H+MbPeShVmYq3t6w9z$C&F)J@NcRfTjWnZr4u7x!A%D*G-KaPdSgVkXp2s5v8y/B?E(H+MbQeThWmZq3t6w9z$C&F)J@NcRfUjXn2r5u7x!A%D*G-KaPdSgVkYp3s6v9y/B?E(H+MbQ"

// setCmd represents the set command
var setCmd = &cobra.Command{
	Use:     "set",
	Aliases: strings.Fields("encrypt"),
	Short:   "Set or encrypt the password with alternate password",
	RunE: func(cmd *cobra.Command, args []string) error {
		showText, err := cmd.Flags().GetBool("text")
		if err != nil {
			return err
		}

		password := strings.Join(args, " ")

		// invalidPass := strings.ContainsAny(password, " ")
		// if invalidPass {
		// 	fmt.Println("The password cannot have spaces.")
		// 	return nil
		// }

		keyFlags, err := cmd.Flags().GetString("key")
		if err != nil {
			return err
		}
		keyPass := strings.TrimSpace(keyFlags)
		if keyPass == "" {
			fmt.Println("The key cannot be empty.")
			return nil
		}

		nameFlags, err := cmd.Flags().GetString("name")
		if err != nil {
			return err
		}
		name := strings.TrimSpace(nameFlags)
		shortenedName := strings.ReplaceAll(name, " ", "")
		shortenedName = strings.ToLower(shortenedName)

		// Encryption occurs here
		cipherText, _, err := encrypt(password, keyPass)
		if err != nil {
			return err
		}

		if showText {
			fmt.Printf("The encrypted data is : %s \n", cipherText)
			return nil
		}

		newPassec := tools.NewPassec(name, cipherText)
		jsonData, err := newPassec.EncodeJson()
		if err != nil {
			return err
		}

		ex, err := os.Executable()
		if err != nil {
			return err
		}

		exPath := filepath.Dir(ex)
		storePath := filepath.Join(exPath, "store")
		err = os.MkdirAll(storePath, os.ModePerm)
		if err != nil {
			return err
		}

		f, err := os.Create(filepath.Join(storePath, shortenedName+".passec"))
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = f.WriteString(jsonData)
		if err != nil {
			return err
		}
		f.Sync()

		fmt.Println("The password has been encrypted and stored in file : ")
		fmt.Printf("%s\n", filepath.Join(storePath, shortenedName+".passec"))

		return nil
	},
}

func encrypt(password string, keyPass string) (string, string, error) {
	dk := pbkdf2.Key([]byte(keyPass), []byte(salt), 4096, 32, sha512.New)
	keyString := hex.EncodeToString(dk)

	key, _ := hex.DecodeString(keyString)

	text := []byte(password)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}

	cipherText := gcm.Seal(nonce, nonce, text, nil)

	return hex.EncodeToString(cipherText), keyString, nil
}

func init() {
	rootCmd.AddCommand(setCmd)
	// setCmd.PersistentFlags().String("foo", "", "A help for foo")
	// setCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	setCmd.Flags().BoolP("text", "t", false, "Display encrypted password as text instead of saving to file")
	setCmd.Flags().StringP("key", "k", "", "The secure key used to encrypt the password")
	setCmd.Flags().StringP("name", "n", "", "Name of the application that uses the password")
	setCmd.MarkFlagRequired("key")
	setCmd.MarkFlagRequired("name")
}
