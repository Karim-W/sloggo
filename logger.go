package sloggo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"io"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func getEncoder() zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.TimeEncoder(func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(time.Now().UTC().Format("2006-01-02T15:04:05.999999")) // this is the format of the time added to the log
		//You can add more strings to log by using enc.AppendString("whatever you want")
	})
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	return zapcore.NewConsoleEncoder(encoderConfig)
}

type _SecretWriter struct {
	buff   io.Writer
	pubKey *rsa.PublicKey
}

// salt the input provided
func (s *_SecretWriter) Encrypt(input []byte) []byte {
	hash := sha512.New()
	ciphertext, _ := rsa.EncryptOAEP(hash, rand.Reader, s.pubKey, input, nil)
	return Encode(ciphertext)
}

func Encode(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}

func (s *_SecretWriter) Write(p []byte) (n int, err error) {
	// encrypt the input
	encrypted := s.Encrypt(p)
	return s.buff.Write(encrypted)
}

func (s *_SecretWriter) initLogger() { // for logging to the console
	encoder := getEncoder()
	// io.Writer
	core := zapcore.NewCore(encoder, zapcore.AddSync(s), zap.DebugLevel)
	logg := zap.New(core, zap.AddCaller())
	zap.ReplaceGlobals(logg)
}

func ConsoleLogger(
	pubKey *rsa.PublicKey,
) (*zap.Logger, error) {
	// create a new cipher block
	s := &_SecretWriter{
		buff:   os.Stdout,
		pubKey: pubKey,
	}
	s.initLogger()
	return zap.L(), nil
}
