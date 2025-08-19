package configs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Netflix/go-env"
	"github.com/joho/godotenv"
)

func NewConfig() (*Environment, error) {
	var environment Environment

	if err := LoadEnviroment(&environment); err != nil {
		return nil, err
	}

	return &environment, nil
}

func LoadEnviroment(environment *Environment) error {
	if environment == nil {
		return errors.New("environment is nil")
	}

	if err := godotenv.Load(); err != nil {
		return err
	}

	if _, err := env.UnmarshalFromEnviron(environment); err != nil {
		return fmt.Errorf("load environment variables: %w", err)
	}

	// Carregar chaves principais (para compatibilidade)
	if environment.Key.PrivateKey == "" || environment.Key.PublicKey == "" {
		privateKey, err := LoadKeyFromFile("../ecdsa_private.pem")
		if err != nil {
			return fmt.Errorf("load private key: %w", err)
		}

		publicKey, err := LoadKeyFromFile("../ecdsa_public.pem")
		if err != nil {
			return fmt.Errorf("load public key: %w", err)
		}

		environment.Key.PrivateKey = privateKey
		environment.Key.PublicKey = publicKey
	}

	// Carregar chaves específicas para OTP
	if environment.Key.OTPPrivateKey == "" || environment.Key.OTPPublicKey == "" {
		otpPrivateKey, err := LoadKeyFromFile("../ecdsa_otp_private.pem")
		if err != nil {
			return fmt.Errorf("load OTP private key: %w", err)
		}

		otpPublicKey, err := LoadKeyFromFile("../ecdsa_otp_public.pem")
		if err != nil {
			return fmt.Errorf("load OTP public key: %w", err)
		}

		environment.Key.OTPPrivateKey = otpPrivateKey
		environment.Key.OTPPublicKey = otpPublicKey
	}

	// Carregar chaves específicas para Access Token
	if environment.Key.AccessTokenPrivateKey == "" || environment.Key.AccessTokenPublicKey == "" {
		accessTokenPrivateKey, err := LoadKeyFromFile("../ecdsa_access_token_private.pem")
		if err != nil {
			return fmt.Errorf("load Access Token private key: %w", err)
		}

		accessTokenPublicKey, err := LoadKeyFromFile("../ecdsa_access_token_public.pem")
		if err != nil {
			return fmt.Errorf("load Access Token public key: %w", err)
		}

		environment.Key.AccessTokenPrivateKey = accessTokenPrivateKey
		environment.Key.AccessTokenPublicKey = accessTokenPublicKey
	}

	// Carregar chaves específicas para Refresh Token
	if environment.Key.RefreshTokenPrivateKey == "" || environment.Key.RefreshTokenPublicKey == "" {
		refreshTokenPrivateKey, err := LoadKeyFromFile("../ecdsa_refresh_token_private.pem")
		if err != nil {
			return fmt.Errorf("load Refresh Token private key: %w", err)
		}

		refreshTokenPublicKey, err := LoadKeyFromFile("../ecdsa_refresh_token_public.pem")
		if err != nil {
			return fmt.Errorf("load Refresh Token public key: %w", err)
		}

		environment.Key.RefreshTokenPrivateKey = refreshTokenPrivateKey
		environment.Key.RefreshTokenPublicKey = refreshTokenPublicKey
	}

	return nil
}

func LoadKeyFromFile(filename string) (string, error) {
	_, currentFile, _, _ := runtime.Caller(0)
	baseDir := filepath.Dir(currentFile)
	fullPath := filepath.Join(baseDir, filename)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", fullPath, err)
	}

	return strings.TrimSpace(string(data)), nil
}
