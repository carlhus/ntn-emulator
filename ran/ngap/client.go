package ngap

import (
	"encoding/binary"
	"fmt"
	"net"

	"ntn-emulator/ran/gtp"

	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/ngap/message"
	"github.com/free5gc/sctp"

	"test"
	"test/ngapTestpacket"
)

// NGAPClient handles NGAP transport layer communication
type NGAPClient struct {
	amfN2IP   string
	ranN2IP   string
	amfN2Port int
	ranN2Port int
	conn      *sctp.SCTPConn
}

// NewNGAPClient creates a new NGAP client
func NewNGAPClient(amfN2IP, ranN2IP string, amfN2Port, ranN2Port int) *NGAPClient {
	return &NGAPClient{
		amfN2IP:   amfN2IP,
		ranN2IP:   ranN2IP,
		amfN2Port: amfN2Port,
		ranN2Port: ranN2Port,
	}
}

// Connect establishes SCTP connection to AMF
func (c *NGAPClient) Connect() error {
	amfAddr, ranAddr, err := c.getSCTPAddresses()
	if err != nil {
		return fmt.Errorf("failed to resolve SCTP addresses: %w", err)
	}

	conn, err := sctp.DialSCTP("sctp", ranAddr, amfAddr)
	if err != nil {
		return fmt.Errorf("failed to dial SCTP connection: %w", err)
	}

	c.conn = conn
	return nil
}

// Close closes the NGAP connection
func (c *NGAPClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Send sends an NGAP message to AMF with correct SCTP PPID
func (c *NGAPClient) Send(data []byte) (int, error) {
	if c.conn == nil {
		return 0, fmt.Errorf("NGAP connection not established")
	}

	// NGAP requires SCTP PPID = 60 (0x3c)
	info := &sctp.SndRcvInfo{
		Stream: 0,
		PPID:   0x3c000000,
	}

	return c.conn.SCTPWrite(data, info)
}

// Receive receives an NGAP message from AMF
func (c *NGAPClient) Receive(buffer []byte) (int, error) {
	if c.conn == nil {
		return 0, fmt.Errorf("NGAP connection not established")
	}
	return c.conn.Read(buffer)
}

// GetConnection returns the underlying SCTP connection
func (c *NGAPClient) GetConnection() *sctp.SCTPConn {
	return c.conn
}

// SendInitialUEMessage sends Initial UE Message (for first Registration Request)
func (c *NGAPClient) SendInitialUEMessage(ranUeNgapID int64, nasPdu []byte, plmnID ie.PLMNIdentity, tai ie.TAI) error {
	// Build NGAP Initial UE Message with correct RRC Establishment Cause for MO-signalling
	pdu := buildInitialUEMessageForRegistration(ranUeNgapID, nasPdu, plmnID, tai)

	//Encode NGAP PDU
	ngapMsg, err := pdu.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to encode Initial UE Message: %w", err)
	}

	// Send via SCTP
	_, err = c.Send(ngapMsg)
	return err
}

// SendUplinkNASTransport sends Uplink NAS Transport (for subsequent NAS messages)
func (c *NGAPClient) SendUplinkNASTransport(amfUeNgapID, ranUeNgapID int64, nasPdu []byte) error {
	// Build NGAP Uplink NAS Transport using test package
	pdu := ngapTestpacket.BuildUplinkNasTransport(amfUeNgapID, ranUeNgapID, nasPdu)

	// Encode NGAP PDU
	ngapMsg, err := pdu.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to encode Uplink NAS Transport: %w", err)
	}

	// Send via SCTP
	_, err = c.Send(ngapMsg)
	return err
}

// SendInitialContextSetupResponse sends Initial Context Setup Response
func (c *NGAPClient) SendInitialContextSetupResponse(amfUeNgapID, ranUeNgapID int64) error {
	// Build and encode NGAP Initial Context Setup Response using test package
	// Note: test.GetInitialContextSetupResponse already returns encoded bytes
	ngapMsg, err := test.GetInitialContextSetupResponse(amfUeNgapID, ranUeNgapID)
	if err != nil {
		return fmt.Errorf("failed to build Initial Context Setup Response: %w", err)
	}

	// Send via SCTP
	_, err = c.Send(ngapMsg)
	return err
}

// ReceiveNASPDU receives and decodes NGAP message, extracts NAS PDU
// Returns NAS PDU bytes and any AMF/RAN UE NGAP IDs if present
func (c *NGAPClient) ReceiveNASPDU() (nasPdu []byte, amfUeNgapID *int64, ranUeNgapID *int64, err error) {
	nasPdu, amfID, ranID, _, err := c.ReceiveNASPDUWithType()
	return nasPdu, amfID, ranID, err
}

// ReceiveNASPDUWithType receives NAS PDU and returns the NGAP message type
// Returns: nasPdu, amfUeNgapID, ranUeNgapID, isInitialContextSetup, error
// isInitialContextSetup = true means this is Registration Accept in Initial Context Setup Request
// isInitialContextSetup = false means this is intermediate message in Downlink NAS Transport
func (c *NGAPClient) ReceiveNASPDUWithType() (nasPdu []byte, amfUeNgapID *int64, ranUeNgapID *int64, isInitialContextSetup bool, err error) {
	// Receive NGAP message
	recvBuf := make([]byte, 65535)
	n, err := c.Receive(recvBuf)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("failed to receive NGAP message: %w", err)
	}

	// Decode NGAP PDU
	pdu, err := message.Parse(recvBuf[:n])
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("failed to decode NGAP PDU: %w", err)
	}

	// Extract NAS PDU from Downlink NAS Transport or Initial Context Setup Request
	switch msg := pdu.(type) {
	case *message.DownlinkNASTransport:
		amfUeNgapID, ranUeNgapID = ngapIDs(msg.AMFUENGAPID, msg.RANUENGAPID)
		if msg.NASPDU == nil {
			return nil, nil, nil, false, fmt.Errorf("NAS PDU not found in Downlink NAS Transport")
		}

		return msg.NASPDU.Value, amfUeNgapID, ranUeNgapID, false, nil

	case *message.InitialContextSetupRequest:
		amfUeNgapID, ranUeNgapID = ngapIDs(msg.AMFUENGAPID, msg.RANUENGAPID)
		if msg.NASPDU == nil {
			return nil, nil, nil, false, fmt.Errorf("NAS PDU not found in Initial Context Setup Request")
		}

		fmt.Println("DEBUG: Received Initial Context Setup Request with NAS PDU")
		return msg.NASPDU.Value, amfUeNgapID, ranUeNgapID, true, nil

	case *message.PDUSessionResourceSetupRequest:
		amfUeNgapID, ranUeNgapID = ngapIDs(msg.AMFUENGAPID, msg.RANUENGAPID)
		if msg.NASPDU == nil {
			return nil, nil, nil, false, fmt.Errorf("NAS PDU not found in PDU Session Resource Setup Request")
		}

		fmt.Println("DEBUG: Received PDU Session Resource Setup Request with NAS PDU")
		return msg.NASPDU.Value, amfUeNgapID, ranUeNgapID, false, nil
	}

	return nil, nil, nil, false, fmt.Errorf("unexpected NGAP message type %T (not Downlink NAS Transport or Initial Context Setup)", pdu)
}

// ngapIDs returns the AMF/RAN UE NGAP ID values of the given IEs, or nil for absent IEs
func ngapIDs(amfIE *ie.AMFUENGAPID, ranIE *ie.RANUENGAPID) (amfUeNgapID *int64, ranUeNgapID *int64) {
	if amfIE != nil {
		id := amfIE.Value
		amfUeNgapID = &id
	}
	if ranIE != nil {
		id := ranIE.Value
		ranUeNgapID = &id
	}
	return amfUeNgapID, ranUeNgapID
}

// getSCTPAddresses resolves and returns SCTP addresses for AMF and RAN
func (c *NGAPClient) getSCTPAddresses() (*sctp.SCTPAddr, *sctp.SCTPAddr, error) {
	amfIps := make([]net.IPAddr, 0)
	ranIps := make([]net.IPAddr, 0)

	// Resolve AMF IP
	if ip, err := net.ResolveIPAddr("ip", c.amfN2IP); err != nil {
		return nil, nil, fmt.Errorf("failed to resolve AMF N2 IP '%s': %w", c.amfN2IP, err)
	} else {
		amfIps = append(amfIps, *ip)
	}

	amfAddr := &sctp.SCTPAddr{
		IPAddrs: amfIps,
		Port:    c.amfN2Port,
	}

	// Resolve RAN IP
	if ip, err := net.ResolveIPAddr("ip", c.ranN2IP); err != nil {
		return nil, nil, fmt.Errorf("failed to resolve RAN N2 IP '%s': %w", c.ranN2IP, err)
	} else {
		ranIps = append(ranIps, *ip)
	}

	ranAddr := &sctp.SCTPAddr{
		IPAddrs: ranIps,
		Port:    0, // Use ephemeral port for client connection
	}

	return amfAddr, ranAddr, nil
}

// PDUSessionSetupInfo contains information from PDU Session Resource Setup Request
type PDUSessionSetupInfo struct {
	PDUSessionID uint8
	UEIPAddress  string
	UPFTEID      uint32
	UPFAddress   string
	UPFPort      int
	NASPdu       []byte
}

// ReceivePDUSessionResourceSetupRequest receives and parses PDU Session Resource Setup Request
func (c *NGAPClient) ReceivePDUSessionResourceSetupRequest() (*PDUSessionSetupInfo, error) {
	// Receive NGAP message
	recvBuf := make([]byte, 65535)
	n, err := c.Receive(recvBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to receive NGAP message: %w", err)
	}

	// Decode NGAP PDU
	pdu, err := message.Parse(recvBuf[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to decode NGAP PDU: %w", err)
	}

	// Verify it's PDU Session Resource Setup Request
	setupReq, ok := pdu.(*message.PDUSessionResourceSetupRequest)
	if !ok {
		return nil, fmt.Errorf("expected PDU Session Resource Setup Request, got %T", pdu)
	}

	info := &PDUSessionSetupInfo{
		UPFPort: 2152, // Default GTP-U port
	}

	// Extract IEs from PDU Session Resource Setup List
	if setupReq.PDUSessionResourceSetupListSUReq != nil {
		for _, item := range setupReq.PDUSessionResourceSetupListSUReq.List {
			// Extract PDU Session ID
			if item.PDUSessionID != nil {
				info.PDUSessionID = uint8(item.PDUSessionID.Value)
			}

			// Extract NAS PDU if present
			if item.PDUSessionNASPDU != nil {
				info.NASPdu = item.PDUSessionNASPDU.Value
			}

			// Decode PDU Session Resource Setup Request Transfer
			if item.PDUSessionResourceSetupRequestTransfer != nil {
				transfer, err := c.decodePDUSessionResourceSetupRequestTransfer(
					*item.PDUSessionResourceSetupRequestTransfer)
				if err != nil {
					return nil, fmt.Errorf("failed to decode transfer: %w", err)
				}

				info.UEIPAddress = transfer.UEIPAddress
				info.UPFTEID = transfer.UPFTEID
				info.UPFAddress = transfer.UPFAddress
			}
		}
	}

	return info, nil
}

// decodePDUSessionResourceSetupRequestTransfer decodes the transfer IE
func (c *NGAPClient) decodePDUSessionResourceSetupRequestTransfer(transferBytes []byte) (*PDUSessionSetupInfo, error) {
	var transfer ie.PDUSessionResourceSetupRequestTransfer
	err := ie.UnmarshalBinary(transferBytes, &transfer)
	if err != nil {
		return nil, fmt.Errorf("APER unmarshal failed: %w", err)
	}

	info := &PDUSessionSetupInfo{}

	if transfer.ProtocolIEs == nil {
		return info, nil
	}

	for _, item := range transfer.ProtocolIEs.List {
		// Extract UPF address and TEID
		if item.ULNGUUPTNLInformation == nil {
			continue
		}
		tunnel, ok := item.ULNGUUPTNLInformation.Choice.(*ie.GTPTunnel)
		if !ok || tunnel.GTPTEID == nil || tunnel.TransportLayerAddress == nil {
			continue
		}

		// Extract TEID
		teid, err := gtp.ParseTEID(tunnel.GTPTEID.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse TEID: %w", err)
		}
		info.UPFTEID = teid

		// Extract UPF IP address
		ipBytes := tunnel.TransportLayerAddress.Value.Bytes
		if len(ipBytes) >= 4 {
			info.UPFAddress = fmt.Sprintf("%d.%d.%d.%d",
				ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
		}
	}

	return info, nil
}

// ReceiveUEContextReleaseCommand waits for UEContextReleaseCommand from AMF after deregistration
func (c *NGAPClient) ReceiveUEContextReleaseCommand() (amfUeNgapID int64, ranUeNgapID int64, err error) {
	recvBuf := make([]byte, 65535)
	n, err := c.Receive(recvBuf)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to receive NGAP message: %w", err)
	}

	pdu, err := message.Parse(recvBuf[:n])
	if err != nil {
		return 0, 0, fmt.Errorf("failed to decode NGAP PDU: %w", err)
	}

	relCmd, ok := pdu.(*message.UEContextReleaseCommand)
	if !ok {
		return 0, 0, fmt.Errorf("expected UEContextReleaseCommand, got %T", pdu)
	}

	if relCmd.UENGAPIDs != nil {
		if pair, ok := relCmd.UENGAPIDs.Choice.(*ie.UENGAPIDPair); ok {
			if pair.AMFUENGAPID != nil {
				amfUeNgapID = pair.AMFUENGAPID.Value
			}
			if pair.RANUENGAPID != nil {
				ranUeNgapID = pair.RANUENGAPID.Value
			}
		}
	}

	return amfUeNgapID, ranUeNgapID, nil
}

// SendUEContextReleaseComplete sends UEContextReleaseComplete to AMF
func (c *NGAPClient) SendUEContextReleaseComplete(amfUeNgapID, ranUeNgapID int64) error {
	pdu := &message.UEContextReleaseComplete{
		AMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapID},
	}

	ngapMsg, err := pdu.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to encode UEContextReleaseComplete: %w", err)
	}

	_, err = c.Send(ngapMsg)
	return err
}

// SendPDUSessionResourceSetupResponse sends PDU Session Resource Setup Response
func (c *NGAPClient) SendPDUSessionResourceSetupResponse(amfUeNgapID, ranUeNgapID int64, pduSessionID uint8, gnbTEID uint32) error {
	// Use default RAN N2 IP (control plane IP)
	return c.SendPDUSessionResourceSetupResponseWithIP(amfUeNgapID, ranUeNgapID, pduSessionID, gnbTEID, c.ranN2IP)
}

// SendPDUSessionResourceSetupResponseWithIP sends PDU Session Resource Setup Response with custom gNB IP
func (c *NGAPClient) SendPDUSessionResourceSetupResponseWithIP(amfUeNgapID, ranUeNgapID int64, pduSessionID uint8, gnbTEID uint32, gnbN3IP string) error {
	// Build PDU Session Resource Setup Response manually
	pdu, err := buildPDUSessionResourceSetupResponsePDU(amfUeNgapID, ranUeNgapID, pduSessionID, gnbTEID, gnbN3IP)
	if err != nil {
		return fmt.Errorf("failed to build PDU session resource setup response: %w", err)
	}

	// Encode NGAP PDU
	ngapMsg, err := pdu.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to encode PDU session resource setup response: %w", err)
	}

	// Send via SCTP
	_, err = c.Send(ngapMsg)
	return err
}

// buildPDUSessionResourceSetupResponsePDU builds the NGAP PDU for PDU Session Resource Setup Response
func buildPDUSessionResourceSetupResponsePDU(amfUeNgapID, ranUeNgapID int64, pduSessionID uint8, gnbTEID uint32, gnbIP string) (*message.PDUSessionResourceSetupResponse, error) {
	// Build PDU Session Resource Setup Response Transfer
	transfer := buildPDUSessionResourceSetupResponseTransfer(gnbTEID, gnbIP)
	transferBytes, err := ie.MarshalBinary(&transfer)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PDU session resource setup response transfer: %w", err)
	}
	transferOctets := aper.OctetString(transferBytes)

	fmt.Printf("📤 NGAP: Sending PDU Session Resource Setup Response with gNB IP=%s, TEID=0x%08x\n", gnbIP, gnbTEID)

	return &message.PDUSessionResourceSetupResponse{
		AMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapID},
		PDUSessionResourceSetupListSURes: &ie.PDUSessionResourceSetupListSURes{
			List: []ie.PDUSessionResourceSetupItemSURes{
				{
					PDUSessionID:                            &ie.PDUSessionID{Value: int64(pduSessionID)},
					PDUSessionResourceSetupResponseTransfer: &transferOctets,
				},
			},
		},
	}, nil
}

// buildPDUSessionResourceSetupResponseTransfer builds the transfer IE
func buildPDUSessionResourceSetupResponseTransfer(gnbTEID uint32, gnbIP string) ie.PDUSessionResourceSetupResponseTransfer {
	// Set gNB TEID
	teidBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(teidBytes, gnbTEID)

	return ie.PDUSessionResourceSetupResponseTransfer{
		DLQosFlowPerTNLInformation: &ie.QosFlowPerTNLInformation{
			// DL GTP Tunnel (gNB side)
			UPTransportLayerInformation: &ie.UPTransportLayerInformation{
				Choice: &ie.GTPTunnel{
					TransportLayerAddress: IPv4ToTransportLayerAddress(gnbIP),
					GTPTEID:               &ie.GTPTEID{Value: aper.OctetString(teidBytes)},
				},
			},
			// Associated QoS Flow List (QFI=1)
			AssociatedQosFlowList: &ie.AssociatedQosFlowList{
				List: []ie.AssociatedQosFlowItem{
					{QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 1}},
				},
			},
		},
	}
}

// IPv4ToTransportLayerAddress converts an IPv4 address string to an NGAP TransportLayerAddress (like free-ran-ue)
func IPv4ToTransportLayerAddress(ipv4Addr string) *ie.TransportLayerAddress {
	ip := net.ParseIP(ipv4Addr).To4()
	if ip == nil {
		return &ie.TransportLayerAddress{}
	}
	return &ie.TransportLayerAddress{
		Value: aper.BitString{
			Bytes:     []byte{ip[0], ip[1], ip[2], ip[3]},
			BitLength: 32,
		},
	}
}

// buildInitialUEMessageForRegistration builds Initial UE Message with MO-Signalling RRC Establishment Cause
// This is critical for AMF to properly initialize UE context with correct access type
func buildInitialUEMessageForRegistration(ranUeNgapID int64, nasPdu []byte, plmnID ie.PLMNIdentity, tai ie.TAI) *message.InitialUEMessage {
	nrPLMNIdentity := plmnID
	return &message.InitialUEMessage{
		// RAN UE NGAP ID
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapID},
		// NAS-PDU
		NASPDU: &ie.NASPDU{Value: aper.OctetString(nasPdu)},
		// User Location Information: set PLMN and Cell ID from config
		UserLocationInformation: &ie.UserLocationInformation{
			Choice: &ie.UserLocationInformationNR{
				NRCGI: &ie.NRCGI{
					PLMNIdentity: &nrPLMNIdentity,
					NRCellIdentity: &ie.NRCellIdentity{
						Value: aper.BitString{
							Bytes:     []byte{0x00, 0x00, 0x00, 0x00, 0x10},
							BitLength: 36,
						},
					},
				},
				TAI: &ie.TAI{
					PLMNIdentity: tai.PLMNIdentity,
					TAC:          tai.TAC,
				},
			},
		},
		// RRC Establishment Cause (use MT Access like free-ran-ue)
		RRCEstablishmentCause: &ie.RRCEstablishmentCause{Value: ie.RRCEstablishmentCausePresentMtAccess},
		// UE Context Request - CRITICAL: Tells AMF to create UE context with proper access type
		UEContextRequest: &ie.UEContextRequest{Value: ie.UEContextRequestPresentRequested},
	}
}
