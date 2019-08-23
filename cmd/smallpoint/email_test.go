package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"testing"
)

type mockIOWriteCloser struct {
	isClosed bool
	Buffer   bytes.Buffer
}

func (m *mockIOWriteCloser) Write(p []byte) (int, error) {
	if m.isClosed {
		return 0, fmt.Errorf("is closed")
	}
	return m.Buffer.Write(p)
}
func (m *mockIOWriteCloser) Close() error {
	m.isClosed = true
	log.Printf("%s", m.Buffer.String())
	return nil
}

type smtpDialerMock struct {
	Buffer mockIOWriteCloser
}

func (*smtpDialerMock) Close() error {
	return nil
}
func (*smtpDialerMock) Mail(from string) error {
	return nil
}
func (*smtpDialerMock) Rcpt(to string) error {
	return nil
}
func (mock *smtpDialerMock) Data() (io.WriteCloser, error) {
	return &mock.Buffer, nil
}

func TestSuccessRequestemail(t *testing.T) {
	state, err := setupTestState()
	if err != nil {
		t.Fatal(err)
	}
	smtpClient = func(addr string) (smtpDialer, error) {
		client := &smtpDialerMock{}
		return client, nil
	}
	err = state.SuccessRequestemail("username", []string{"admin@example.com"},
		"somegroup", "127.0.0.1", "mycecret uA")
	if err != nil {
		t.Fatal(err)
	}
}
