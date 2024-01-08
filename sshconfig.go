package sshconfig

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func loadFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

//********** SSHSigner

type SSHSigner struct {
	PrivateKeyFile string `json:"private-key" yaml:"private-key" toml:"private-key"`
	PrivateKeyData string `json:"private-key-data" yaml:"private-key-data" toml:"private-key-data"`
}

func (s SSHSigner) toSigner() (ssh.Signer, error) {
	if s.PrivateKeyFile != "" && s.PrivateKeyData != "" {
		return nil, fmt.Errorf("private-key and private-key-data are mutual exclusive")
	}
	keyData := []byte(s.PrivateKeyData)
	if s.PrivateKeyFile != "" {
		var err error
		if keyData, err = loadFile(s.PrivateKeyFile); err != nil {
			return nil, fmt.Errorf("failed to load private-key: %v", err)
		}
	}
	key, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to load private-key: %v", err)
	}
	return key, nil
}

//********** SSHAuthMethod

type SSHAuthMethod struct {
	Password     *string     `json:"password" yaml:"password" toml:"password"`
	PasswordFile *string     `json:"password-file" yaml:"password-file" toml:"password-file"`
	PublicKeys   []SSHSigner `json:"public-keys" yaml:"public-keys" toml:"public-keys"`
}

//********** SSHHostKey

type SSHHostKey struct {
	InsecureIgnore bool   `json:"insecure-ignore" yaml:"insecure-ignore" toml:"insecure-ignore"`
	PublicKeyFile  string `json:"public-key" yaml:"public-key" toml:"public-key"`
	PublicKeyData  string `json:"public-key-data" yaml:"public-key-data" toml:"public-key-data"`
}

func (h SSHHostKey) toHostKeyCallback() (ssh.HostKeyCallback, error) {
	if h.InsecureIgnore {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	if h.PublicKeyFile != "" && h.PublicKeyData != "" {
		return nil, fmt.Errorf("public-key and public-key-data are mutual exclusive")
	}
	keyData := []byte(h.PublicKeyData)
	if h.PublicKeyFile != "" {
		var err error
		if keyData, err = loadFile(h.PublicKeyFile); err != nil {
			return nil, fmt.Errorf("failed to load public-key: %v", err)
		}
	}
	_, _, key, _, _, err := ssh.ParseKnownHosts(bytes.Join([][]byte{[]byte("*"), keyData}, []byte(" ")))
	if err != nil {
		return nil, fmt.Errorf("failed to load public-key: %v", err)
	}
	return ssh.FixedHostKey(key), nil
}

//********** SSHBaseConfig

type SSHBaseConfig struct {
	RekeyThreshold uint64   `json:"rekey-threshold" yaml:"rekey-threshold" toml:"rekey-threshold"`
	KeyExchanges   []string `json:"key-exchanges" yaml:"key-exchanges" toml:"key-exchanges"`
	Ciphers        []string `json:"ciphers" yaml:"ciphers" toml:"ciphers"`
	MACs           []string `json:"macs" yaml:"macs" toml:"macs"`
}

//********** SSHClientConfig

type SSHClientConfig struct {
	SSHBaseConfig
	User              string          `json:"user" yaml:"user" toml:"user"`
	ClientVersion     string          `json:"client-version" yaml:"client-version" toml:"client-version"`
	HostKeyAlgorithms []string        `json:"host-key-algorithms" yaml:"host-key-algorithms" toml:"host-key-algorithms"`
	Timeout           time.Duration   `json:"timeout" yaml:"timeout" toml:"timeout"`
	Auth              []SSHAuthMethod `json:"auth" yaml:"auth" toml:"auth"`
	HostKey           SSHHostKey      `json:"host-key" yaml:"host-key" toml:"host-key"`
}

func (cc SSHClientConfig) ToGoSSHClientConfig() (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{}

	cfg.RekeyThreshold = cc.RekeyThreshold
	cfg.KeyExchanges = cc.KeyExchanges
	cfg.Ciphers = cc.Ciphers
	cfg.MACs = cc.MACs

	cfg.User = cc.User
	cfg.ClientVersion = cc.ClientVersion
	cfg.HostKeyAlgorithms = cc.HostKeyAlgorithms
	cfg.Timeout = cc.Timeout

	for _, auth := range cc.Auth {
		if auth.Password != nil {
			cfg.Auth = append(cfg.Auth, ssh.Password(*auth.Password))
		}
		if auth.PasswordFile != nil {
			passwordData, err := loadFile(*auth.PasswordFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load password from file: %v", err)
			}
			password, _, _ := strings.Cut(string(passwordData), "\n")
			cfg.Auth = append(cfg.Auth, ssh.Password(password))
		}
		for _, key := range auth.PublicKeys {
			var signers []ssh.Signer
			signer, err := key.toSigner()
			if err != nil {
				return nil, err
			}
			signers = append(signers, signer)
			cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signers...))
		}
	}

	var err error
	if cfg.HostKeyCallback, err = cc.HostKey.toHostKeyCallback(); err != nil {
		return nil, err
	}
	return cfg, nil
}

//********** SSHServerConfig

type SSHServerConfig struct {
	SSHBaseConfig
	PublicKeyAuthAlgorithms []string    `json:"public-key-auth-algorithms" yaml:"public-key-auth-algorithms" toml:"public-key-auth-algorithms"`
	NoClientAuth            bool        `json:"no-client-auth" yaml:"no-client-auth" toml:"no-client-auth"`
	MaxAuthTries            int         `json:"max-auth-tries" yaml:"max-auth-tries" toml:"max-auth-tries"`
	ServerVersion           string      `json:"server-version" yaml:"server-version" toml:"server-version"`
	HostKeys                []SSHSigner `json:"host-keys" yaml:"host-keys" toml:"host-keys"`
}

func (sc SSHServerConfig) ToGoSSHServerConfig() (*ssh.ServerConfig, error) {
	cfg := &ssh.ServerConfig{}

	cfg.RekeyThreshold = sc.RekeyThreshold
	cfg.KeyExchanges = sc.KeyExchanges
	cfg.Ciphers = sc.Ciphers
	cfg.MACs = sc.MACs

	cfg.PublicKeyAuthAlgorithms = sc.PublicKeyAuthAlgorithms
	cfg.NoClientAuth = sc.NoClientAuth
	cfg.MaxAuthTries = sc.MaxAuthTries
	cfg.ServerVersion = sc.ServerVersion
	for _, hostKey := range sc.HostKeys {
		signer, err := hostKey.toSigner()
		if err != nil {
			return nil, err
		}
		cfg.AddHostKey(signer)
	}
	return cfg, nil
}
