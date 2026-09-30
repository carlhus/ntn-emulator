package ran

import (
	"fmt"

	"ntn-emulator/ran/ngap"
	"ntn-emulator/ue"
	uenas "ntn-emulator/ue/nas"

	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// PDUSessionHandler handles PDU Session Establishment procedure
type PDUSessionHandler struct {
	ue     *ue.UEContext
	codec  *uenas.NASCodec
	client *ngap.NGAPClient
}

// NewPDUSessionHandler creates a new PDU Session handler
func NewPDUSessionHandler(uectx *ue.UEContext, codec *uenas.NASCodec, client *ngap.NGAPClient) *PDUSessionHandler {
	return &PDUSessionHandler{
		ue:     uectx,
		codec:  codec,
		client: client,
	}
}

// EstablishPDUSession performs PDU Session Establishment procedure
func (h *PDUSessionHandler) EstablishPDUSession(pduSessionID uint8, dnn string, sNssai *models.Snssai) error {
	h.ue.SetState(ue.UEStateEstablishingPDU)
	h.ue.PDUSessionID = pduSessionID

	// Step 1: Build and send PDU Session Establishment Request
	if err := h.sendPDUSessionEstablishmentRequest(pduSessionID, dnn, sNssai); err != nil {
		return fmt.Errorf("failed to send PDU session establishment request: %w", err)
	}

	// Step 2: Receive and handle PDU Session Resource Setup Request
	if err := h.handlePDUSessionResourceSetup(); err != nil {
		return fmt.Errorf("failed to handle PDU session resource setup: %w", err)
	}

	// Step 3: Receive PDU Session Establishment Accept
	if err := h.receivePDUSessionEstablishmentAccept(); err != nil {
		return fmt.Errorf("failed to receive PDU session establishment accept: %w", err)
	}

	h.ue.SetState(ue.UEStatePDUActive)
	return nil
}

// sendPDUSessionEstablishmentRequest sends PDU Session Establishment Request
func (h *PDUSessionHandler) sendPDUSessionEstablishmentRequest(pduSessionID uint8, dnn string, sNssai *models.Snssai) error {
	// Build PDU Session Establishment Request
	pduSessionRequest, err := uenas.BuildPDUSessionEstablishmentRequest(pduSessionID)
	if err != nil {
		return fmt.Errorf("failed to build PDU session request: %w", err)
	}

	// Build UL NAS Transport message
	ulNasTransport := uenas.BuildULNASTransport(pduSessionRequest, pduSessionID, dnn, sNssai)

	// Encode with security
	encodedMsg, err := h.codec.Encode(ulNasTransport,
		message.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return fmt.Errorf("failed to encode UL NAS transport: %w", err)
	}

	// Send via NGAP Uplink NAS Transport
	err = h.client.SendUplinkNASTransport(h.ue.AmfUeNgapId, h.ue.RanUeNgapId, encodedMsg)
	if err != nil {
		return fmt.Errorf("failed to send PDU session request: %w", err)
	}

	fmt.Printf("✓ PDU Session Establishment Request sent (Session ID: %d)\n", pduSessionID)
	return nil
}

// receivePDUSessionEstablishmentAccept receives PDU Session Establishment Accept
func (h *PDUSessionHandler) receivePDUSessionEstablishmentAccept() error {
	// Receive NGAP message and extract NAS PDU
	nasPduBytes, _, _, err := h.client.ReceiveNASPDU()
	if err != nil {
		return fmt.Errorf("failed to receive NAS PDU: %w", err)
	}

	// Decode NAS message
	nasPdu, err := h.codec.Decode(nasPduBytes)
	if err != nil {
		return fmt.Errorf("failed to decode NAS message: %w", err)
	}

	// Verify message type (should be DL NAS Transport)
	fmt.Printf("DEBUG: Received message type: %T\n", nasPdu)

	// Check if it's Configuration Update Command
	if _, ok := nasPdu.(*message.CfgUpdateCmd); ok {
		fmt.Println("Received Configuration Update Command, sending Complete...")
		// Handle Configuration Update - send Configuration Update Complete
		encodedMsg, err := h.codec.Encode(uenas.BuildConfigurationUpdateComplete(), message.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
		if err != nil {
			return fmt.Errorf("failed to encode config update complete: %w", err)
		}

		err = h.client.SendUplinkNASTransport(h.ue.AmfUeNgapId, h.ue.RanUeNgapId, encodedMsg)
		if err != nil {
			return fmt.Errorf("failed to send config update complete: %w", err)
		}

		fmt.Println("✓ Configuration Update Complete sent")

		// Now receive the actual PDU Session Establishment Accept
		return h.receivePDUSessionEstablishmentAccept()
	}

	// Extract PDU Session Establishment Accept from DL NAS Transport
	if _, err := uenas.ExtractPDUSessionEstablishmentAccept(nasPdu); err != nil {
		return err
	}

	fmt.Println("✓ PDU Session Establishment Accept received")
	return nil
}

// handlePDUSessionResourceSetup handles PDU Session Resource Setup Request and Response
func (h *PDUSessionHandler) handlePDUSessionResourceSetup() error {
	// This will receive PDU Session Resource Setup Request from AMF
	// Extract TEID, UPF address, and UE IP
	// Send PDU Session Resource Setup Response
	// Setup GTP-U tunnel and TUN interface

	fmt.Println("Waiting for PDU Session Resource Setup Request...")

	// Receive NGAP PDU Session Resource Setup Request
	pduSessionSetup, err := h.client.ReceivePDUSessionResourceSetupRequest()
	if err != nil {
		return fmt.Errorf("failed to receive PDU session resource setup request: %w", err)
	}

	fmt.Println("✓ Received PDU Session Resource Setup Request")
	fmt.Printf("  UPF TEID: 0x%08x\n", pduSessionSetup.UPFTEID)
	fmt.Printf("  UPF Address: %s:%d\n", pduSessionSetup.UPFAddress, pduSessionSetup.UPFPort)

	// Extract UE IP from NAS PDU (PDU Session Establishment Accept)
	if len(pduSessionSetup.NASPdu) > 0 {
		ueIP, err := h.extractUEIPFromNASPdu(pduSessionSetup.NASPdu)
		if err != nil {
			fmt.Printf("  Warning: Failed to extract UE IP from NAS PDU: %v\n", err)
		} else if ueIP != "" {
			pduSessionSetup.UEIPAddress = ueIP
		}
	}

	if pduSessionSetup.UEIPAddress == "" {
		return fmt.Errorf("no UE IP address found in PDU Session Resource Setup Request")
	}

	fmt.Printf("  UE IP Address: %s\n", pduSessionSetup.UEIPAddress)

	// Store UE IP address
	h.ue.UEIPAddress = pduSessionSetup.UEIPAddress

	// Generate TEIDs
	// Uplink TEID: RAN → UPF (RAN uses this when forwarding to UPF)
	uplinkTEID := pduSessionSetup.UPFTEID
	// Downlink TEID: UPF → RAN (UPF uses this when sending to RAN)
	downlinkTEID := uint32(h.ue.RanUeNgapId)

	// Store TEIDs in UE context (for separated architecture)
	h.ue.UPFTEID = uplinkTEID
	h.ue.RANTEID = downlinkTEID

	// Note: In the new free-ran-ue architecture:
	// - RAN process handles data plane server and GTP-U encapsulation
	// - UE process creates TUN and connects to RAN via simple UDP (no GTP at UE side)
	// - RAN should NOT create TUN interface

	fmt.Printf("✓ PDU Session established: UE IP=%s, UPF TEID=0x%08x, RAN TEID=0x%08x\n",
		pduSessionSetup.UEIPAddress, uplinkTEID, downlinkTEID)

	return nil
}

// extractUEIPFromNASPdu extracts UE IP address from PDU Session Establishment Accept NAS PDU
func (h *PDUSessionHandler) extractUEIPFromNASPdu(nasPdu []byte) (string, error) {
	// Decode NAS PDU
	decodedNas, err := h.codec.Decode(nasPdu)
	if err != nil {
		return "", fmt.Errorf("failed to decode NAS PDU: %w", err)
	}

	// Extract PDU Session Establishment Accept from DL NAS Transport
	pduEstabAccept, err := uenas.ExtractPDUSessionEstablishmentAccept(decodedNas)
	if err != nil {
		return "", err
	}

	// Get PDU Address (IPv4 address)
	if ueIP, ok := uenas.PDUAddressIPv4(pduEstabAccept); ok {
		return ueIP, nil
	}

	return "", fmt.Errorf("no PDU address found")
}

// EstablishPDUSessionForSeparateUE performs PDU Session Establishment for separated UE/RAN architecture
// This is used when UE runs as a separate process
func (h *PDUSessionHandler) EstablishPDUSessionForSeparateUE(pduSessionID uint8, dnn string, sNssai *models.Snssai, ueN3IP string) error {
	h.ue.SetState(ue.UEStateEstablishingPDU)
	h.ue.PDUSessionID = pduSessionID

	// Step 1: Build and send PDU Session Establishment Request
	if err := h.sendPDUSessionEstablishmentRequest(pduSessionID, dnn, sNssai); err != nil {
		return fmt.Errorf("failed to send PDU session establishment request: %w", err)
	}

	// Step 2: Receive and handle PDU Session Resource Setup Request
	if err := h.handlePDUSessionResourceSetupForSeparateUE(ueN3IP); err != nil {
		return fmt.Errorf("failed to handle PDU session resource setup: %w", err)
	}

	// Note: In separated architecture, RAN doesn't wait for PDU Session Establishment Accept
	// The UE process will handle that separately when it connects

	h.ue.SetState(ue.UEStatePDUActive)
	return nil
}

// handlePDUSessionResourceSetupForSeparateUE handles PDU session setup for separated UE/RAN
// In this architecture:
// - RAN only handles control plane (NGAP/NAS)
// - UE will run as separate process with its own GTP-U tunnel directly to UPF
func (h *PDUSessionHandler) handlePDUSessionResourceSetupForSeparateUE(ueN3IP string) error {
	fmt.Println("Waiting for PDU Session Resource Setup Request...")

	// Receive NGAP PDU Session Resource Setup Request
	pduSessionSetup, err := h.client.ReceivePDUSessionResourceSetupRequest()
	if err != nil {
		return fmt.Errorf("failed to receive PDU session resource setup request: %w", err)
	}

	fmt.Println("✓ Received PDU Session Resource Setup Request")
	fmt.Printf("  UPF TEID: 0x%08x\n", pduSessionSetup.UPFTEID)
	fmt.Printf("  UPF Address: %s:%d\n", pduSessionSetup.UPFAddress, pduSessionSetup.UPFPort)

	// Extract UE IP from NAS PDU
	if len(pduSessionSetup.NASPdu) > 0 {
		ueIP, err := h.extractUEIPFromNASPdu(pduSessionSetup.NASPdu)
		if err != nil {
			fmt.Printf("  Warning: Failed to extract UE IP from NAS PDU: %v\n", err)
		} else if ueIP != "" {
			pduSessionSetup.UEIPAddress = ueIP
		}
	}

	if pduSessionSetup.UEIPAddress == "" {
		return fmt.Errorf("no UE IP address found in PDU Session Resource Setup Request")
	}

	fmt.Printf("  UE IP Address: %s\n", pduSessionSetup.UEIPAddress)

	// Store session information in UE context
	h.ue.UEIPAddress = pduSessionSetup.UEIPAddress
	h.ue.UPFTEID = pduSessionSetup.UPFTEID
	h.ue.RANTEID = uint32(h.ue.RanUeNgapId) // Use RAN UE NGAP ID as downlink TEID

	// Send PDU Session Resource Setup Response
	// Tell SMF/UPF to send downlink GTP-U packets to ueN3IP:2152
	err = h.client.SendPDUSessionResourceSetupResponseWithIP(
		h.ue.AmfUeNgapId,
		h.ue.RanUeNgapId,
		h.ue.PDUSessionID,
		h.ue.RANTEID,
		ueN3IP, // UE's N3 IP address (where UE will listen for GTP-U)
	)
	if err != nil {
		return fmt.Errorf("failed to send PDU session resource setup response: %w", err)
	}

	fmt.Println("✓ PDU Session Resource Setup Response sent")
	fmt.Printf("  Told UPF to send downlink to: %s:2152 with TEID 0x%08x\n", ueN3IP, h.ue.RANTEID)

	return nil
}
