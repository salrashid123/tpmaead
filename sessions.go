package tpmaead

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type Session interface {
	GetSession(rwr transport.TPM, setTrial bool) (auth tpm2.Session, closer func() error, err error)
}

type NoPolicySession struct{}

func NewNoPolicySession() (NoPolicySession, error) {
	return NoPolicySession{}, nil
}

func (p NoPolicySession) GetSession(rwr transport.TPM, setTrial bool) (auth tpm2.Session, closer func() error, err error) {

	var sess tpm2.Session
	var sesscleanup func() error

	if setTrial {
		sess, sesscleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial()}...)
		if err != nil {
			return nil, nil, err
		}

	} else {
		sess, sesscleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{}...)
		if err != nil {
			return nil, nil, err
		}
	}
	return sess, sesscleanup, nil
}

type PCRSession struct {
	sel    tpm2.TPMLPCRSelection
	digest tpm2.TPM2BDigest
}

func NewPCRSession(sel tpm2.TPMLPCRSelection, digest tpm2.TPM2BDigest) (PCRSession, error) {
	return PCRSession{sel, digest}, nil
}

func (p PCRSession) GetSession(rwr transport.TPM, setTrial bool) (auth tpm2.Session, closer func() error, err error) {

	var sess tpm2.Session
	var sesscleanup func() error

	if setTrial {
		sess, sesscleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial()}...)
		if err != nil {
			return nil, nil, err
		}

	} else {
		sess, sesscleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest:     p.digest,
		Pcrs:          p.sel,
	}.Execute(rwr)
	if err != nil {
		return nil, sesscleanup, err
	}

	return sess, sesscleanup, nil
}

type PolicyAuthValueSession struct {
	password []byte
}

func NewPolicyAuthValueSession(password []byte) (PolicyAuthValueSession, error) {
	return PolicyAuthValueSession{password}, nil
}

func (p PolicyAuthValueSession) GetSession(rwr transport.TPM, setTrial bool) (auth tpm2.Session, closer func() error, err error) {

	var sess tpm2.Session
	var sesscleanup func() error

	if setTrial {
		sess, sesscleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial()}...)
		if err != nil {
			return nil, nil, err
		}

	} else {
		sess, sesscleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth(p.password)}...)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		return nil, sesscleanup, err
	}

	return sess, sesscleanup, nil
}

type PCRAndPolicyAuthValueSession struct {
	sel      tpm2.TPMLPCRSelection
	digest   tpm2.TPM2BDigest
	password []byte
}

func NewPCRAndAuthValueSession(sel tpm2.TPMLPCRSelection, digest tpm2.TPM2BDigest, password []byte) (PCRAndPolicyAuthValueSession, error) {
	return PCRAndPolicyAuthValueSession{sel, digest, password}, nil
}

func (p PCRAndPolicyAuthValueSession) GetSession(rwr transport.TPM, setTrial bool) (auth tpm2.Session, closer func() error, err error) {

	var sess tpm2.Session
	var sesscleanup func() error

	if setTrial {
		sess, sesscleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial()}...)
		if err != nil {
			return nil, nil, err
		}

	} else {
		sess, sesscleanup, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth(p.password)}...)
		if err != nil {
			return nil, nil, err
		}
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest:     p.digest,
		Pcrs:          p.sel,
	}.Execute(rwr)
	if err != nil {
		return nil, sesscleanup, err
	}

	_, err = tpm2.PolicyAuthValue{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		return nil, sesscleanup, err
	}

	return sess, sesscleanup, nil
}
