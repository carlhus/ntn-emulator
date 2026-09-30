package nas

import (
	"errors"
	"fmt"
	"strings"

	"ntn-emulator/ue"

	"test"

	"github.com/free-ran-ue/util"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
)

// NASCodec handles NAS message encoding and decoding
type NASCodec struct {
	ue *ue.UEContext
}

// NewNASCodec creates a new NAS codec for the given UE context
func NewNASCodec(uectx *ue.UEContext) *NASCodec {
	return &NASCodec{ue: uectx}
}

// Decode decodes a NAS message, verifying and deciphering it when it is security protected
func (nc *NASCodec) Decode(payload []byte) (message.Message, error) {
	// Use test package's NASDecode to handle security
	return test.NASDecode(nc.ue.RanUeContext, message.GetSecHdrType(payload), payload)
}

// Encode encodes a NAS message with security
func (nc *NASCodec) Encode(nasMessage message.Message, securityHeaderType message.SecHdrType,
	securityContextAvailable, newSecurityContext bool) ([]byte, error) {
	if nasMessage == nil {
		return nil, errors.New("NAS message is nil")
	}

	// Use test package's NASEncode for consistency (plain encoding when no security context)
	return test.NASEncode(nc.ue.RanUeContext, nasMessage, securityHeaderType, securityContextAvailable, newSecurityContext)
}

// EncodeBytes encodes already-encoded NAS message bytes with security
func (nc *NASCodec) EncodeBytes(payload []byte, securityHeaderType message.SecHdrType,
	securityContextAvailable, newSecurityContext bool) ([]byte, error) {
	if !securityContextAvailable {
		return payload, nil
	}

	return test.EncodeNasPduWithSecurity(nc.ue.RanUeContext, payload, securityHeaderType, true, newSecurityContext)
}

// BuildMobileIdentity5GS builds Mobile Identity 5GS from SUPI
func BuildMobileIdentity5GS(supi string) (*ie.MobileId5GS, error) {
	// util.SupiToBytes expects pure digits without "imsi-" prefix
	// supi format: "imsi-208930000000001" -> need "208930000000001"
	imsi := strings.TrimPrefix(supi, "imsi-")
	// 3-digit MCC and 2-digit MNC (e.g. 208/93)
	supiBytes := util.SupiToBytes(3, 2, imsi)

	mobileIdentity5GS := new(ie.MobileId5GS)
	if err := mobileIdentity5GS.UnmarshalBinary(supiBytes); err != nil {
		return nil, fmt.Errorf("failed to build mobile identity 5GS: %w", err)
	}
	return mobileIdentity5GS, nil
}

// BuildUESecurityCapability builds UE Security Capability
func BuildUESecurityCapability(cipheringAlg ie.AlgCiphering, integrityAlg ie.AlgIntegrity) *ie.UESecCapability {
	ueSecurityCapability := &ie.UESecCapability{
		Length: 2,
	}

	// Set ciphering algorithm
	switch cipheringAlg {
	case message.AlgCiphering128NEA0:
		ueSecurityCapability.EA05G = true
	case message.AlgCiphering128NEA1:
		ueSecurityCapability.EA1_128_5G = true
	case message.AlgCiphering128NEA2:
		ueSecurityCapability.EA2_128_5G = true
	case message.AlgCiphering128NEA3:
		ueSecurityCapability.EA3_128_5G = true
	}

	// Set integrity algorithm
	switch integrityAlg {
	case message.AlgIntegrity128NIA0:
		ueSecurityCapability.IA05G = true
	case message.AlgIntegrity128NIA1:
		ueSecurityCapability.IA1_128_5G = true
	case message.AlgIntegrity128NIA2:
		ueSecurityCapability.IA2_128_5G = true
	case message.AlgIntegrity128NIA3:
		ueSecurityCapability.IA3_128_5G = true
	}

	return ueSecurityCapability
}

// BuildRegistrationRequest builds a plain-encoded Registration Request NAS message
func BuildRegistrationRequest(registrationType uint8, mobileIdentity5GS *ie.MobileId5GS,
	ueSecurityCapability *ie.UESecCapability, capability5GMM *ie.Capability5GMM) ([]byte, error) {

	registrationRequest := &message.RegReq{
		RegType5GS: &ie.RegType5GS{
			FOR_Pending: true,
			Value:       registrationType,
		},
		Ngksi: &ie.NASKeySetId{
			Tsc: ie.SecCtxTypeNative,
			Ksi: ie.NASKeyNA,
		},
		MobileId5GS:     mobileIdentity5GS,
		UESecCapability: ueSecurityCapability,
		Capability5GMM:  capability5GMM,
	}

	buf, err := registrationRequest.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode registration request: %w", err)
	}

	return buf, nil
}

// BuildAuthenticationResponse builds a plain-encoded Authentication Response NAS message
func BuildAuthenticationResponse(resStar []byte) ([]byte, error) {
	authResponse := &message.AuthRsp{
		AuthRspParam: &ie.AuthRspParam{
			Res: resStar,
		},
	}

	buf, err := authResponse.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode authentication response: %w", err)
	}

	return buf, nil
}

// BuildSecurityModeComplete builds a Security Mode Complete NAS message
func BuildSecurityModeComplete(registrationRequest []byte) *message.SecModeComplete {
	securityModeComplete := &message.SecModeComplete{}

	if registrationRequest != nil {
		securityModeComplete.NASMsgCntr = &ie.NASMsgCntr{Contents: registrationRequest}
	}

	return securityModeComplete
}

// BuildRegistrationComplete builds a Registration Complete NAS message
func BuildRegistrationComplete() *message.RegComplete {
	return &message.RegComplete{}
}

// BuildIdentityResponse builds Identity Response message with Mobile Identity
func BuildIdentityResponse(supi string) (*message.IdRsp, error) {
	return BuildIdentityResponseWithType(supi, ie.IdType_5GS_SUCI)
}

// BuildIdentityResponseWithType builds Identity Response with specific identity type
func BuildIdentityResponseWithType(supi string, identityType uint8) (*message.IdRsp, error) {
	var mobileIdentity *ie.MobileId5GS

	switch identityType {
	case ie.IdType_5GS_SUCI: // Type 1: SUCI (SUPI)
		mobileIdentity5GS, err := BuildMobileIdentity5GS(supi)
		if err != nil {
			return nil, err
		}
		mobileIdentity = mobileIdentity5GS
	case ie.IdType_5GS_IMEI: // Type 3: IMEI
		// Build IMEI (15 digits): 490154203237518 (valid checksum)
		mobileIdentity = &ie.MobileId5GS{
			TypeOfId:     ie.IdType_5GS_IMEI,
			OddEvenIndic: ie.OddNumOfIdDigit,
			IMEI:         [15]uint8{4, 9, 0, 1, 5, 4, 2, 0, 3, 2, 3, 7, 5, 1, 8},
		}
	case ie.IdType_5GS_IMEISV: // Type 5: IMEISV
		// Build IMEISV if requested (use dummy for now)
		// Dummy IMEISV: 35609204079301 (14 digits) + software version 10
		mobileIdentity = &ie.MobileId5GS{
			TypeOfId:     ie.IdType_5GS_IMEISV,
			OddEvenIndic: ie.EvenNumOfIdDigit,
			IMEISV:       [16]uint8{3, 5, 6, 0, 9, 2, 0, 4, 0, 7, 9, 3, 0, 1, 1, 0},
		}
	default:
		// For other types, use SUCI as fallback
		fmt.Printf("WARNING: Unsupported identity type %d requested, using SUCI\n", identityType)
		mobileIdentity5GS, err := BuildMobileIdentity5GS(supi)
		if err != nil {
			return nil, err
		}
		mobileIdentity = mobileIdentity5GS
	}

	return &message.IdRsp{MobileId: mobileIdentity}, nil
}

// BuildConfigurationUpdateComplete builds Configuration Update Complete message
func BuildConfigurationUpdateComplete() *message.CfgUpdateComplete {
	return &message.CfgUpdateComplete{}
}
