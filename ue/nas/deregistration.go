package nas

import (
	"fmt"
	"net"

	"ntn-emulator/util"
	"ntn-emulator/ue"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
)

// DeregistrationHandler handles UE Deregistration procedure
type DeregistrationHandler struct {
	ue             *ue.UEContext
	codec          *NASCodec
	ranControlConn net.Conn
}

// NewDeregistrationHandler creates a new Deregistration handler
func NewDeregistrationHandler(uectx *ue.UEContext, codec *NASCodec, ranControlConn net.Conn) *DeregistrationHandler {
	return &DeregistrationHandler{
		ue:             uectx,
		codec:          codec,
		ranControlConn: ranControlConn,
	}
}

// PerformDeregistration performs the complete UE Deregistration procedure
func (h *DeregistrationHandler) PerformDeregistration(switchOff bool) error {
	h.ue.SetState(ue.UEStateDeregistering)

	fmt.Println("\n[Deregistration] Starting UE-initiated deregistration...")

	// Step 1: Send Deregistration Request
	if err := h.sendDeregistrationRequest(switchOff); err != nil {
		return fmt.Errorf("failed to send deregistration request: %w", err)
	}

	// Step 2: Receive Deregistration Accept
	if err := h.handleDeregistrationAccept(); err != nil {
		return fmt.Errorf("failed to handle deregistration accept: %w", err)
	}

	h.ue.SetState(ue.UEStateIdle)
	fmt.Println("✓ Deregistration completed successfully")

	return nil
}

// sendDeregistrationRequest sends UE-originated Deregistration Request
func (h *DeregistrationHandler) sendDeregistrationRequest(switchOff bool) error {
	// Build Mobile Identity 5GS
	mobileIdentity, err := BuildMobileIdentity5GS(h.ue.Supi)
	if err != nil {
		return err
	}

	// Build Deregistration Request
	var switchOffValue uint8
	if switchOff {
		switchOffValue = 0x01 // Switch off
	} else {
		switchOffValue = 0x00 // Normal detach
	}

	deregRequest := BuildDeregistrationRequest(
		ie.AccessType_3gpp,
		switchOffValue,
		0x07, // ngKSI (same as used in registration)
		mobileIdentity,
	)

	// Encode with security
	encodedMsg, err := h.codec.Encode(deregRequest,
		message.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return fmt.Errorf("failed to encode deregistration request: %w", err)
	}

	// Send via Uplink NAS Transport
	// Send plain NAS PDU to RAN control plane via TCP
	if err := util.WriteMessage(h.ranControlConn, encodedMsg); err != nil {
		return fmt.Errorf("failed to send deregistration request: %w", err)
	}
	fmt.Printf("[Deregistration] Sent %d bytes to RAN\n", len(encodedMsg))

	fmt.Println("✓ Deregistration Request sent")
	return nil
}

// handleDeregistrationAccept receives Deregistration Accept from network
func (h *DeregistrationHandler) handleDeregistrationAccept() error {
	// Receive plain NAS PDU from RAN control plane via TCP
	nasPduBytes, err := util.ReadMessage(h.ranControlConn)
	if err != nil {
		// Check if this is a timeout (AMF might have processed deregistration but not sent accept)
		return fmt.Errorf("failed to receive deregistration accept: %w (Note: deregistration may still have succeeded on network side)", err)
	}
	fmt.Printf("[Deregistration] Received %d bytes from RAN\n", len(nasPduBytes))

	// Decode NAS message
	nasPdu, err := h.codec.Decode(nasPduBytes)
	if err != nil {
		return fmt.Errorf("failed to decode NAS message: %w", err)
	}

	// Verify message type
	if _, ok := nasPdu.(*message.DeregAcceptUEOrig); !ok {
		// Check if we got a reject or other error
		fmt.Printf("⚠️  Warning: Expected Deregistration Accept (0x46), got %T\n", nasPdu)
		return fmt.Errorf("expected Deregistration Accept (UE-originating), got %T", nasPdu)
	}

	fmt.Println("✓ Deregistration Accept received")
	return nil
}

// BuildDeregistrationRequest builds a Deregistration Request NAS message (UE-originated)
func BuildDeregistrationRequest(accessType, switchOff, ngKsi uint8, mobileIdentity5GS *ie.MobileId5GS) *message.DeregReqUEOrig {
	return &message.DeregReqUEOrig{
		// Set deregistration type
		DeregType: &ie.DeregType{
			Switchoff:     switchOff&0x1 == 1,
			ReregRequired: false,
			AccessType:    accessType & 0x3,
		},
		Ngksi: &ie.NASKeySetId{
			Tsc: ie.SecCtxType(ngKsi & 0x1),
			Ksi: ngKsi & 0x7,
		},
		// Set mobile identity
		MobileId5GS: mobileIdentity5GS,
	}
}
