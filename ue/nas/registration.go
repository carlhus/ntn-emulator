package nas

import (
	"encoding/hex"
	"fmt"
	"net"

	"ntn-emulator/ue"
	"ntn-emulator/util"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/milenage"
)

// RegistrationHandler handles UE Registration procedure
type RegistrationHandler struct {
	ue             *ue.UEContext
	codec          *NASCodec
	ranControlConn net.Conn // TCP connection to RAN control plane
}

// NewRegistrationHandler creates a new Registration handler
func NewRegistrationHandler(uectx *ue.UEContext, codec *NASCodec, ranControlConn net.Conn) *RegistrationHandler {
	return &RegistrationHandler{
		ue:             uectx,
		codec:          codec,
		ranControlConn: ranControlConn,
	}
}

// PerformRegistration performs the complete UE Registration procedure
func (h *RegistrationHandler) PerformRegistration() error {
	h.ue.SetState(ue.UEStateRegistering)

	// Step 1: Send Registration Request
	if err := h.sendRegistrationRequest(); err != nil {
		return fmt.Errorf("failed to send registration request: %w", err)
	}

	// Step 2: Receive and handle Authentication Request
	if err := h.handleAuthenticationRequest(); err != nil {
		return fmt.Errorf("failed to handle authentication request: %w", err)
	}

	// Step 3: Receive and handle Security Mode Command
	if err := h.handleSecurityModeCommand(); err != nil {
		return fmt.Errorf("failed to handle security mode command: %w", err)
	}

	// Step 4: Receive Registration Accept and send Registration Complete
	if err := h.handleRegistrationAccept(); err != nil {
		return fmt.Errorf("failed to handle registration accept: %w", err)
	}

	// Step 5: Receive Configuration Update Command (optional)
	if err := h.handleConfigurationUpdate(); err != nil {
		// Configuration update is optional, just log warning
		fmt.Printf("Warning: Configuration update handling: %v\n", err)
	}

	h.ue.SetState(ue.UEStateRegistered)
	return nil
}

// sendRegistrationRequest sends initial Registration Request to RAN
func (h *RegistrationHandler) sendRegistrationRequest() error {
	// Build Mobile Identity 5GS
	mobileIdentity, err := BuildMobileIdentity5GS(h.ue.Supi)
	if err != nil {
		return err
	}

	// Build UE Security Capability
	ueSecurityCapability := BuildUESecurityCapability(h.ue.CipheringAlg, h.ue.IntegrityAlg)

	// Build Registration Request (initial, without 5GMM capability)
	regRequest, err := BuildRegistrationRequest(
		ie.RegType_InitialReg,
		mobileIdentity,
		ueSecurityCapability,
		nil, // No 5GMM capability yet
	)
	if err != nil {
		return fmt.Errorf("failed to build registration request: %w", err)
	}

	// Send plain NAS PDU to RAN control plane via TCP
	if err := util.WriteMessage(h.ranControlConn, regRequest); err != nil {
		return fmt.Errorf("failed to send registration request: %w", err)
	}
	fmt.Printf("Sent %d bytes of registration request to RAN\n", len(regRequest))

	return nil
}

// handleAuthenticationRequest receives and responds to Authentication Request
func (h *RegistrationHandler) handleAuthenticationRequest() error {
	// Receive plain NAS PDU from RAN control plane via TCP
	nasPduBytes, err := util.ReadMessage(h.ranControlConn)
	if err != nil {
		return fmt.Errorf("failed to receive authentication request: %w", err)
	}
	fmt.Printf("Received %d bytes of authentication request from RAN\n", len(nasPduBytes))

	// Decode NAS message
	nasPdu, err := h.codec.Decode(nasPduBytes)
	if err != nil {
		return fmt.Errorf("failed to decode NAS message: %w", err)
	}

	// Verify message type
	authRequest, ok := nasPdu.(*message.AuthReq)
	if !ok {
		return fmt.Errorf("expected Authentication Request, got %T", nasPdu)
	}

	// Extract RAND and AUTN
	if authRequest.AuthParamRAND5GAuthChlg == nil || authRequest.AuthParamAUTN5GAuthChlg == nil {
		return fmt.Errorf("authentication request missing RAND or AUTN")
	}
	rand := authRequest.AuthParamRAND5GAuthChlg.Rand
	autn := authRequest.AuthParamAUTN5GAuthChlg.Autn

	// CRITICAL: Extract and update SQN from AUTN BEFORE deriving keys.
	// DeriveRESstarAndSetKey uses authSubs.SequenceNumber.Sqn to compute SQNxorAK
	// inside DerivateKamf. The network derives Kamf with the SQN from the AUTN.
	// If localSQN != networkSQN, SQNxorAK differs → wrong Kamf → MAC failures on re-registration.
	if newSQN, err := extractSQNFromAUTN(autn, rand, h.ue.AuthenticationSubs); err == nil {
		if h.ue.AuthenticationSubs.SequenceNumber != nil {
			oldSQN := h.ue.AuthenticationSubs.SequenceNumber.Sqn
			h.ue.AuthenticationSubs.SequenceNumber.Sqn = newSQN
			fmt.Printf("✓ SQN synchronized: %s -> %s (from network AUTN)\n", oldSQN, newSQN)
		}
	} else {
		fmt.Printf("⚠️  Warning: Could not extract SQN from AUTN: %v\n", err)
		fmt.Println("   Continuing with current SQN (may cause issues on re-registration)")
	}

	// Derive RES* and NAS keys from the new Kamf using the network's SQN (just updated above).
	// DeriveRESstarAndSetKey internally calls DerivateAlgKey() to compute KnasEnc/KnasInt.
	resStar := h.ue.DeriveRESstarAndSetKey(h.ue.AuthenticationSubs, rand, "5G:mnc093.mcc208.3gppnetwork.org")

	// Build and send Authentication Response
	authResponse, err := BuildAuthenticationResponse(resStar)
	if err != nil {
		return fmt.Errorf("failed to build authentication response: %w", err)
	}

	// Send plain NAS PDU to RAN control plane via TCP
	if err := util.WriteMessage(h.ranControlConn, authResponse); err != nil {
		return fmt.Errorf("failed to send authentication response: %w", err)
	}
	fmt.Printf("Sent %d bytes of authentication response to RAN\n", len(authResponse))

	return nil
}

// handleSecurityModeCommand receives Security Mode Command and responds with Complete
func (h *RegistrationHandler) handleSecurityModeCommand() error {
	// Receive plain NAS PDU from RAN control plane via TCP
	nasPduBytes, err := util.ReadMessage(h.ranControlConn)
	if err != nil {
		return fmt.Errorf("failed to receive security mode command: %w", err)
	}
	fmt.Printf("Received %d bytes of security mode command from RAN\n", len(nasPduBytes))

	// Debug: print first few bytes
	if len(nasPduBytes) > 0 {
		fmt.Printf("DEBUG: Received NAS PDU, first bytes: %02x\n", nasPduBytes[:min(16, len(nasPduBytes))])
	}

	// Decode NAS message
	nasPdu, err := h.codec.Decode(nasPduBytes)
	if err != nil {
		return fmt.Errorf("failed to decode NAS message: %w", err)
	}

	// Verify message type
	secModeCmd, ok := nasPdu.(*message.SecModeCmd)
	if !ok {
		return fmt.Errorf("expected Security Mode Command, got %T", nasPdu)
	}

	// Extract selected NAS security algorithms from Security Mode Command
	// and update the UE context before deriving NAS keys
	if secModeCmd.SelectedNASSecAlgos != nil {
		selectedCiphering := secModeCmd.SelectedNASSecAlgos.CipheringAlgo
		selectedIntegrity := secModeCmd.SelectedNASSecAlgos.MsgIntAlgo
		fmt.Printf("Selected algorithms: ciphering=%d, integrity=%d\n", selectedCiphering, selectedIntegrity)
		h.ue.RanUeContext.CipheringAlg = selectedCiphering
		h.ue.RanUeContext.IntegrityAlg = selectedIntegrity
	}

	// Derive NAS keys (KnasEnc, KnasInt) from the new Kamf established during authentication.
	// This MUST happen before encoding Security Mode Complete so it uses fresh keys.
	h.ue.RanUeContext.DerivateAlgKey()
	fmt.Println("Derived new NAS keys from Kamf")

	// Build Registration Request with 5GMM capability
	mobileIdentity, err := BuildMobileIdentity5GS(h.ue.Supi)
	if err != nil {
		return err
	}
	ueSecurityCapability := BuildUESecurityCapability(h.ue.CipheringAlg, h.ue.IntegrityAlg)
	capability5GMM := h.ue.Get5GMMCapability()

	regRequestWith5GMM, err := BuildRegistrationRequest(
		ie.RegType_InitialReg,
		mobileIdentity,
		ueSecurityCapability,
		capability5GMM,
	)
	if err != nil {
		return fmt.Errorf("failed to build registration request with 5GMM: %w", err)
	}

	// Build Security Mode Complete with embedded Registration Request
	secModeComplete := BuildSecurityModeComplete(regRequestWith5GMM)

	// Encode with security (new security context)
	encodedMsg, err := h.codec.Encode(secModeComplete,
		message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx, true, true)
	if err != nil {
		return fmt.Errorf("failed to encode security mode complete: %w", err)
	}

	// Send Security Mode Complete via Uplink NAS Transport
	// Send plain NAS PDU to RAN control plane via TCP
	if err := util.WriteMessage(h.ranControlConn, encodedMsg); err != nil {
		return fmt.Errorf("failed to send security mode complete: %w", err)
	}
	fmt.Printf("Sent %d bytes of security mode complete to RAN\n", len(encodedMsg))

	return nil
}

// handleRegistrationAccept receives Registration Accept and sends Registration Complete
func (h *RegistrationHandler) handleRegistrationAccept() error {
	// Receive plain NAS PDU from RAN control plane via TCP
	nasPduBytes, err := util.ReadMessage(h.ranControlConn)
	if err != nil {
		return fmt.Errorf("failed to receive registration accept: %w", err)
	}
	fmt.Printf("Received %d bytes of registration accept from RAN\n", len(nasPduBytes))

	// Decode NAS message
	nasPdu, err := h.codec.Decode(nasPduBytes)
	if err != nil {
		return fmt.Errorf("failed to decode NAS message: %w", err)
	}

	// Check if we received Identity Request first
	fmt.Printf("DEBUG: Received message type: %T\n", nasPdu)

	if identityRequest, ok := nasPdu.(*message.IdReq); ok {
		// Check what type of identity is requested
		var requestedType uint8
		if identityRequest.IdType != nil {
			requestedType = identityRequest.IdType.IdType
			fmt.Printf("Identity Request: Type requested = %d\n", requestedType)
		} else {
			return fmt.Errorf("Identity Request has no identity type")
		}

		fmt.Println("Received Identity Request, sending Identity Response...")

		// Build and send Identity Response with requested identity type
		identityResponse, err := BuildIdentityResponseWithType(h.ue.Supi, requestedType)
		if err != nil {
			return fmt.Errorf("failed to build identity response: %w", err)
		}

		// Encode with security
		encodedMsg, err := h.codec.Encode(identityResponse,
			message.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
		if err != nil {
			return fmt.Errorf("failed to encode identity response: %w", err)
		}

		fmt.Printf("DEBUG: Encoded Identity Response (first 32 bytes): %02x\n", encodedMsg[:min(32, len(encodedMsg))])

		fmt.Println("[UE] DEBUG: Sending Identity Response to RAN...")
		if err := util.WriteMessage(h.ranControlConn, encodedMsg); err != nil {
			return fmt.Errorf("failed to send identity response: %w", err)
		}

		fmt.Println("Identity Response sent successfully")

		// Now receive the actual Registration Accept (in Initial Context Setup Request)
		fmt.Println("[UE] DEBUG: Waiting for Registration Accept after Identity Response...")
		nasPduBytes, err = util.ReadMessage(h.ranControlConn)
		if err != nil {
			return fmt.Errorf("failed to receive registration accept after identity: %w", err)
		}
		fmt.Printf("[UE] DEBUG: Received %d bytes after Identity Response\n", len(nasPduBytes))

		nasPdu, err = h.codec.Decode(nasPduBytes)
		if err != nil {
			return fmt.Errorf("failed to decode NAS message: %w", err)
		}

		fmt.Printf("DEBUG: After Identity Response, received message type: %T\n", nasPdu)
	}

	// Verify message type
	if _, ok := nasPdu.(*message.RegAccept); !ok {
		return fmt.Errorf("expected Registration Accept, got %T", nasPdu)
	}

	fmt.Println("✓ Registration Accept received")

	// Send Initial Context Setup Response (if received in Initial Context Setup Request)
	// This is needed to complete the NGAP procedure
	// No InitialContextSetupResponse needed - RAN handles NGAP; err = nil
	if err != nil {
		return fmt.Errorf("failed to send Initial Context Setup Response: %w", err)
	}

	fmt.Println("✓ Initial Context Setup Response sent")

	// Build Registration Complete
	regComplete := BuildRegistrationComplete()

	// Encode with security
	encodedMsg, err := h.codec.Encode(regComplete,
		message.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return fmt.Errorf("failed to encode registration complete: %w", err)
	}

	// Send Registration Complete via Uplink NAS Transport
	// Send plain NAS PDU to RAN control plane via TCP
	if err := util.WriteMessage(h.ranControlConn, encodedMsg); err != nil {
		return fmt.Errorf("failed to send registration complete: %w", err)
	}
	fmt.Printf("Sent %d bytes of registration complete to RAN\n", len(encodedMsg))

	fmt.Println("✓ Registration Complete sent")

	return nil
}

// handleConfigurationUpdate receives Configuration Update Command (optional)
func (h *RegistrationHandler) handleConfigurationUpdate() error {
	// Receive NGAP message and extract NAS PDU (optional, may timeout)
	nasPduBytes, err := util.ReadMessage(h.ranControlConn)
	if err != nil {
		return err // May timeout, which is acceptable
	}

	// Decode NAS message
	nasPdu, err := h.codec.Decode(nasPduBytes)
	if err != nil {
		return fmt.Errorf("failed to decode NAS message: %w", err)
	}

	// Verify message type (optional, just receive and acknowledge)
	if _, ok := nasPdu.(*message.CfgUpdateCmd); !ok {
		return fmt.Errorf("expected Configuration Update Command, got %T", nasPdu)
	}

	fmt.Println("✓ Configuration Update Command received")

	// Send Configuration Update Complete, encoded with security
	encodedMsg, err := h.codec.Encode(BuildConfigurationUpdateComplete(), message.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return fmt.Errorf("failed to encode configuration update complete with security: %w", err)
	}

	// Send to RAN
	if err := util.WriteMessage(h.ranControlConn, encodedMsg); err != nil {
		return fmt.Errorf("failed to send configuration update complete: %w", err)
	}

	fmt.Println("✓ Configuration Update Complete sent")
	return nil
}

// extractSQNFromAUTN extracts and updates the SQN from AUTN
// AUTN format: SQN ⊕ AK (6 bytes) || AMF (2 bytes) || MAC (8 bytes)
// This function derives AK from K, OPC, and RAND, then recovers SQN = (SQN ⊕ AK) ⊕ AK
func extractSQNFromAUTN(autn []byte, rand []byte, authSubs models.Udr_DR_AuthenticationSubscription) (string, error) {
	if len(autn) < 16 {
		return "", fmt.Errorf("invalid AUTN length: %d", len(autn))
	}
	if len(rand) != 16 {
		return "", fmt.Errorf("invalid RAND length: %d", len(rand))
	}

	// Decode K and OPC from hex
	k, err := hex.DecodeString(authSubs.EncPermanentKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode K: %w", err)
	}
	opc, err := hex.DecodeString(authSubs.EncOpcKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode OPC: %w", err)
	}

	// Extract SQN ⊕ AK from AUTN (first 6 bytes)
	sqnXorAK := autn[0:6]

	// Use GenerateKeysWithAUTN to derive AK from the received AUTN
	// This function returns: sqn, ak, ik, ck, res
	_, akDerived, _, _, _, err := milenage.GenerateKeysWithAUTN(opc, k, rand, autn)
	if err != nil {
		return "", fmt.Errorf("failed to derive AK from AUTN: %w", err)
	}

	// Calculate SQN = (SQN ⊕ AK) ⊕ AK
	sqn := make([]byte, 6)
	for i := 0; i < 6; i++ {
		sqn[i] = sqnXorAK[i] ^ akDerived[i]
	}

	return hex.EncodeToString(sqn), nil
}
