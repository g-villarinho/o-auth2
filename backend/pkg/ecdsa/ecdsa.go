package ecdsa

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/aetheris-lab/aetheris-id/api/configs"
)

type EcdsaKeyPair interface {
	ParseECDSAPrivateKey() (*ecdsa.PrivateKey, error)
	ParseECDSAPublicKey() (*ecdsa.PublicKey, error)
	// Novos métodos para chaves específicas
	ParseOTPPrivateKey() (*ecdsa.PrivateKey, error)
	ParseOTPPublicKey() (*ecdsa.PublicKey, error)
	ParseAccessTokenPrivateKey() (*ecdsa.PrivateKey, error)
	ParseAccessTokenPublicKey() (*ecdsa.PublicKey, error)
	ParseRefreshTokenPrivateKey() (*ecdsa.PrivateKey, error)
	ParseRefreshTokenPublicKey() (*ecdsa.PublicKey, error)
}

type ecdsaKeyPair struct {
	config *configs.Environment
}

func NewEcdsaKeyPair(config *configs.Environment) EcdsaKeyPair {
	return &ecdsaKeyPair{
		config: config,
	}
}

func (e *ecdsaKeyPair) ParseECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(e.config.Key.PrivateKey))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("failed to parse EC private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (e *ecdsaKeyPair) ParseECDSAPublicKey() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(e.config.Key.PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to parse EC public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not a valid ECDSA public key")
	}

	return ecdsaPubKey, nil
}

// Métodos para chaves OTP
func (e *ecdsaKeyPair) ParseOTPPrivateKey() (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(e.config.Key.OTPPrivateKey))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("failed to parse OTP EC private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (e *ecdsaKeyPair) ParseOTPPublicKey() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(e.config.Key.OTPPublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to parse OTP EC public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not a valid ECDSA public key")
	}

	return ecdsaPubKey, nil
}

// Métodos para chaves Access Token
func (e *ecdsaKeyPair) ParseAccessTokenPrivateKey() (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(e.config.Key.AccessTokenPrivateKey))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("failed to parse Access Token EC private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (e *ecdsaKeyPair) ParseAccessTokenPublicKey() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(e.config.Key.AccessTokenPublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to parse Access Token EC public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not a valid ECDSA public key")
	}

	return ecdsaPubKey, nil
}

// Métodos para chaves Refresh Token
func (e *ecdsaKeyPair) ParseRefreshTokenPrivateKey() (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(e.config.Key.RefreshTokenPrivateKey))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("failed to parse Refresh Token EC private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (e *ecdsaKeyPair) ParseRefreshTokenPublicKey() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(e.config.Key.RefreshTokenPublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to parse Refresh Token EC public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not a valid ECDSA public key")
	}

	return ecdsaPubKey, nil
}
