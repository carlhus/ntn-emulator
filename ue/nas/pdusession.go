package nas

import (
	"fmt"
	"net"

	"ntn-emulator/util"
	"ntn-emulator/ue"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// PDUSessionHandler handles PDU Session Establishment procedure
type PDUSessionHandler struct {
	ue             *ue.UEContext
	codec          *NASCodec
	ranControlConn net.Conn
}

// NewPDUSessionHandler creates a new PDU Session handler
func NewPDUSessionHandler(uectx *ue.UEContext, codec *NASCodec, ranControlConn net.Conn) *PDUSessionHandler {
	return &PDUSessionHandler{
		ue:             uectx,
		codec:          codec,
		ranControlConn: ranControlConn,
	}
}

// EstablishPDUSession performs PDU Session Establishment procedure
func (h *PDUSessionHandler) EstablishPDUSession(pduSessionID uint8, dnn string, sNssai *models.Snssai) error {
	fmt.Printf("\n[PDU Session] Starting PDU Session Establishment (Session ID: %d, DNN: %s)\n", pduSessionID, dnn)

	// Step 1: Build and send PDU Session Establishment Request
	if err := h.sendPDUSessionEstablishmentRequest(pduSessionID, dnn, sNssai); err != nil {
		return fmt.Errorf("failed to send PDU session establishment request: %w", err)
	}

	// Step 2: Receive PDU Session Establishment Accept
	if err := h.receivePDUSessionEstablishmentAccept(); err != nil {
		return fmt.Errorf("failed to receive PDU session establishment accept: %w", err)
	}

	h.ue.PDUSessionID = pduSessionID
	fmt.Println("✓ PDU Session Establishment completed")
	return nil
}

// sendPDUSessionEstablishmentRequest sends PDU Session Establishment Request
func (h *PDUSessionHandler) sendPDUSessionEstablishmentRequest(pduSessionID uint8, dnn string, sNssai *models.Snssai) error {
	// Step 1: Build PDU Session Establishment Request message
	pduSessionBytes, err := BuildPDUSessionEstablishmentRequest(pduSessionID)
	if err != nil {
		return fmt.Errorf("failed to build PDU session establishment request: %w", err)
	}

	// Step 2: Wrap it in UL NAS Transport message
	ulNasTransport := BuildULNASTransport(pduSessionBytes, pduSessionID, dnn, sNssai)

	// Step 3: Encode with security
	encodedMsg, err := h.codec.Encode(ulNasTransport, message.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return fmt.Errorf("failed to encode UL NAS transport: %w", err)
	}

	// Step 4: Send to RAN
	if err := util.WriteMessage(h.ranControlConn, encodedMsg); err != nil {
		return fmt.Errorf("failed to send PDU session establishment request: %w", err)
	}

	fmt.Printf("✓ PDU Session Establishment Request sent (Session ID: %d)\n", pduSessionID)
	return nil
}

// receivePDUSessionEstablishmentAccept receives PDU Session Establishment Accept
func (h *PDUSessionHandler) receivePDUSessionEstablishmentAccept() error {
	// Receive NAS PDU from RAN
	nasPduBytes, err := util.ReadMessage(h.ranControlConn)
	if err != nil {
		return fmt.Errorf("failed to receive PDU session establishment accept: %w", err)
	}
	fmt.Printf("Received %d bytes from RAN (PDU Session Establishment Accept)\n", len(nasPduBytes))

	// Decode NAS message
	nasPdu, err := h.codec.Decode(nasPduBytes)
	if err != nil {
		return fmt.Errorf("failed to decode NAS message: %w", err)
	}

	// Extract PDU Session Establishment Accept from DL NAS Transport
	pduEstabAccept, err := ExtractPDUSessionEstablishmentAccept(nasPdu)
	if err != nil {
		return err
	}

	fmt.Println("✓ PDU Session Establishment Accept received")

	// Extract UE IP address and other info
	if err := h.extractUEInformation(pduEstabAccept); err != nil {
		return fmt.Errorf("failed to extract UE information: %w", err)
	}

	return nil
}

// extractUEInformation extracts UE IP address, TEIDs from PDU Session Establishment Accept
func (h *PDUSessionHandler) extractUEInformation(pduEstabAccept *message.PDUSessEstAccept) error {
	// Extract PDU Address (UE IP)
	if ueIP, ok := PDUAddressIPv4(pduEstabAccept); ok {
		h.ue.UEIPAddress = ueIP
		fmt.Printf("✓ UE IP Address: %s\n", h.ue.UEIPAddress)
	}

	// Extract Authorized QoS Rules
	if pduEstabAccept.AuthoQosRules != nil {
		fmt.Println("✓ Authorized QoS Rules received")
	}

	// Note: TEIDs are extracted from NGAP PDU Session Resource Setup Request on the RAN side
	// and passed to UE via the data plane or stored in context

	return nil
}

// ExtractPDUSessionEstablishmentAccept extracts the PDU Session Establishment Accept
// carried in the payload container of a DL NAS Transport message
func ExtractPDUSessionEstablishmentAccept(nasPdu message.Message) (*message.PDUSessEstAccept, error) {
	// Verify it's DL NAS Transport
	dlNasTransport, ok := nasPdu.(*message.DLNASTransport)
	if !ok {
		return nil, fmt.Errorf("expected DL NAS Transport, got %T", nasPdu)
	}

	// Extract payload container (contains PDU Session Establishment Accept)
	if dlNasTransport.PayloadCntr == nil || len(dlNasTransport.PayloadCntr.Contents) == 0 {
		return nil, fmt.Errorf("payload container is empty")
	}

	// Decode PDU Session Establishment Accept from payload
	gsmMsg, err := message.ParseGSM(dlNasTransport.PayloadCntr.Contents)
	if err != nil {
		return nil, fmt.Errorf("failed to decode GSM message: %w", err)
	}

	pduEstabAccept, ok := gsmMsg.(*message.PDUSessEstAccept)
	if !ok {
		return nil, fmt.Errorf("expected PDU Session Establishment Accept, got %T", gsmMsg)
	}

	return pduEstabAccept, nil
}

// PDUAddressIPv4 returns the IPv4 PDU address assigned in a PDU Session Establishment Accept
func PDUAddressIPv4(pduEstabAccept *message.PDUSessEstAccept) (string, bool) {
	if pduEstabAccept.PDUAddr == nil || len(pduEstabAccept.PDUAddr.IPv4) < 4 {
		return "", false
	}
	ipBytes := pduEstabAccept.PDUAddr.IPv4
	return fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]), true
}

// BuildPDUSessionEstablishmentRequest builds a plain-encoded PDU Session Establishment Request (like free-ran-ue)
func BuildPDUSessionEstablishmentRequest(pduSessionID uint8) ([]byte, error) {
	pduSessionRequest := &message.PDUSessEstReq{
		PDUSessId: pduSessionID,
		PTI:       0x00,
		IntegrityProtectionMaxDataRate: &ie.IntegrityProtectionMaxDataRate{
			Uplink:   0xff,
			Downlink: 0xff,
		},
		// Set PDU Session Type to IPv4
		PDUSessType: &ie.PDUSessType{
			Value: ie.PDUSessType_IPv4,
		},
		// Set SSC Mode to SSC Mode 1
		SSCMode: &ie.SSCMode{
			Mode: ie.SSCMODE1,
		},
		// Set Extended Protocol Configuration Options
		ExtendedProtCfgOpts: &ie.ExtendedProtCfgOpts{
			FromMs: &ie.ExtCfgOptFromMs{
				DNSV4Req: true,
				DNSV6Req: true,
			},
		},
	}

	return pduSessionRequest.MarshalBinary()
}

// BuildULNASTransport builds UL NAS Transport message wrapping PDU Session Establishment Request (like free-ran-ue)
func BuildULNASTransport(nasMessageContainer []byte, pduSessionID uint8, dnn string, sNssai *models.Snssai) *message.ULNASTransport {
	ulNasTransport := &message.ULNASTransport{
		// Set Payload Container Type and contents
		PayloadCntrType: &ie.PayloadCntrType{
			Value: ie.PayloadCntrType_N1SMInfo,
		},
		PayloadCntr: &ie.PayloadCntr{
			Pct:      ie.PayloadCntrType_N1SMInfo,
			Contents: nasMessageContainer,
		},
		// Set PDU Session ID
		PDUSessID: &ie.PDUSessId2{
			Value: pduSessionID,
		},
		// Set Request Type to Initial Request
		ReqType: &ie.ReqType{
			Value: ie.ReqType_InitialReq,
		},
	}

	// Set DNN if provided
	if dnn != "" {
		ulNasTransport.DNN = &ie.DNN{Value: dnn}
	}

	// Set S-NSSAI if provided (SD is a hex string)
	if sNssai != nil {
		ulNasTransport.SNSSAI = &ie.SNSSAI{
			SST: uint8(sNssai.Sst),
			SD:  sNssai.Sd,
		}
	}

	return ulNasTransport
}
