package ngap

import (
	"fmt"

	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/ngap/message"
)

// PathSwitchHandler handles Path Switch Request procedure (for handover simulation)
type PathSwitchHandler struct {
	client *NGAPClient
}

// NewPathSwitchHandler creates a new Path Switch handler
func NewPathSwitchHandler(client *NGAPClient) *PathSwitchHandler {
	return &PathSwitchHandler{
		client: client,
	}
}

// SendPathSwitchRequest sends a Path Switch Request to AMF
// This is used by the target RAN (RAN-B) to inform AMF about the new path
//
// Parameters:
//   - amfUeNgapID: The AMF UE NGAP ID (from the UE context)
//   - ranUeNgapID: The new RAN UE NGAP ID (assigned by RAN-B)
//   - pduSessionID: The PDU Session ID to switch
//   - newRanN3IP: The new RAN's N3 interface IP address
//   - newDLTEID: The new downlink TEID for this RAN
//   - plmnID: PLMN Identity
//   - nrCellID: NR Cell Identity (36 bits)
//   - tac: Tracking Area Code
//
// Returns error if the request fails
func (h *PathSwitchHandler) SendPathSwitchRequest(
	amfUeNgapID, ranUeNgapID int64,
	pduSessionID uint8,
	newRanN3IP string,
	newDLTEID uint32,
	plmnID ie.PLMNIdentity,
	nrCellID []byte, // 5 bytes for 36-bit NR Cell ID
	tac []byte, // 3 bytes for TAC
) error {
	// Build Path Switch Request message
	pdu, err := h.buildPathSwitchRequest(
		amfUeNgapID,
		ranUeNgapID,
		pduSessionID,
		newRanN3IP,
		newDLTEID,
		plmnID,
		nrCellID,
		tac,
	)
	if err != nil {
		return fmt.Errorf("failed to build Path Switch Request: %w", err)
	}

	// Encode NGAP message
	ngapMsg, err := pdu.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to encode Path Switch Request: %w", err)
	}

	// Send to AMF
	_, err = h.client.Send(ngapMsg)
	if err != nil {
		return fmt.Errorf("failed to send Path Switch Request: %w", err)
	}

	return nil
}

// ReceivePathSwitchRequestAcknowledge receives and processes Path Switch Request Acknowledge
// Returns the UL TEID that UPF expects for uplink packets, or error
func (h *PathSwitchHandler) ReceivePathSwitchRequestAcknowledge() (ulTEID uint32, upfN3IP string, err error) {
	// Receive NGAP message
	recvBuf := make([]byte, 65535)
	n, err := h.client.Receive(recvBuf)
	if err != nil {
		return 0, "", fmt.Errorf("failed to receive Path Switch Request Acknowledge: %w", err)
	}

	// Decode NGAP PDU
	ngapPdu, err := message.Parse(recvBuf[:n])
	if err != nil {
		return 0, "", fmt.Errorf("failed to decode Path Switch Request Acknowledge: %w", err)
	}

	// Verify it's a Path Switch Request Acknowledge
	ack, ok := ngapPdu.(*message.PathSwitchRequestAcknowledge)
	if !ok {
		return 0, "", fmt.Errorf("expected Path Switch Request Acknowledge, got %T", ngapPdu)
	}

	// Extract UL GTP-U tunnel info from PDU Session Resource Switched List
	if ack.PDUSessionResourceSwitchedList != nil {
		for _, item := range ack.PDUSessionResourceSwitchedList.List {
			if item.PathSwitchRequestAcknowledgeTransfer == nil {
				continue
			}

			// Decode PathSwitchRequestAcknowledgeTransfer
			transfer := ie.PathSwitchRequestAcknowledgeTransfer{}
			if err := ie.UnmarshalBinary(*item.PathSwitchRequestAcknowledgeTransfer, &transfer); err != nil {
				return 0, "", fmt.Errorf("failed to decode PathSwitchRequestAcknowledgeTransfer: %w", err)
			}

			// Extract UL NG-U UP TNL Information (UPF's uplink tunnel info)
			if transfer.ULNGUUPTNLInformation == nil {
				continue
			}
			gtpTunnel, ok := transfer.ULNGUUPTNLInformation.Choice.(*ie.GTPTunnel)
			if !ok || gtpTunnel == nil {
				continue
			}

			// Extract TEID
			if gtpTunnel.GTPTEID != nil && len(gtpTunnel.GTPTEID.Value) == 4 {
				ulTEID = uint32(gtpTunnel.GTPTEID.Value[0])<<24 |
					uint32(gtpTunnel.GTPTEID.Value[1])<<16 |
					uint32(gtpTunnel.GTPTEID.Value[2])<<8 |
					uint32(gtpTunnel.GTPTEID.Value[3])
			}

			// Extract UPF N3 IP address
			if gtpTunnel.TransportLayerAddress != nil && len(gtpTunnel.TransportLayerAddress.Value.Bytes) >= 4 {
				ipBytes := gtpTunnel.TransportLayerAddress.Value.Bytes
				upfN3IP = fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
			}

			return ulTEID, upfN3IP, nil
		}
	}

	return 0, "", fmt.Errorf("no UL tunnel information found in Path Switch Request Acknowledge")
}

// buildPathSwitchRequest constructs the Path Switch Request NGAP message
func (h *PathSwitchHandler) buildPathSwitchRequest(
	amfUeNgapID, ranUeNgapID int64,
	pduSessionID uint8,
	newRanN3IP string,
	newDLTEID uint32,
	plmnID ie.PLMNIdentity,
	nrCellID []byte,
	tac []byte,
) (*message.PathSwitchRequest, error) {
	pathSwitchRequestTransfer, err := h.buildPathSwitchRequestTransfer(newRanN3IP, newDLTEID)
	if err != nil {
		return nil, err
	}

	nrPLMNIdentity := plmnID
	taiPLMNIdentity := plmnID
	allAlgorithms := aper.BitString{Bytes: []byte{0xff, 0xff}, BitLength: 16}

	return &message.PathSwitchRequest{
		// 1. RAN UE NGAP ID
		RANUENGAPID: &ie.RANUENGAPID{Value: ranUeNgapID},
		// 2. Source AMF UE NGAP ID (this is the AMF UE NGAP ID from the source RAN)
		SourceAMFUENGAPID: &ie.AMFUENGAPID{Value: amfUeNgapID},
		// 3. User Location Information (new RAN's location)
		UserLocationInformation: &ie.UserLocationInformation{
			Choice: &ie.UserLocationInformationNR{
				NRCGI: &ie.NRCGI{
					PLMNIdentity:   &nrPLMNIdentity,
					NRCellIdentity: &ie.NRCellIdentity{Value: aper.BitString{Bytes: nrCellID, BitLength: 36}},
				},
				TAI: &ie.TAI{
					PLMNIdentity: &taiPLMNIdentity,
					TAC:          &ie.TAC{Value: aper.OctetString(tac)},
				},
			},
		},
		// 4. UE Security Capabilities (copied from UE context)
		UESecurityCapabilities: &ie.UESecurityCapabilities{
			NRencryptionAlgorithms:             &ie.NRencryptionAlgorithms{Value: allAlgorithms},
			NRintegrityProtectionAlgorithms:    &ie.NRintegrityProtectionAlgorithms{Value: allAlgorithms},
			EUTRAencryptionAlgorithms:          &ie.EUTRAencryptionAlgorithms{Value: allAlgorithms},
			EUTRAintegrityProtectionAlgorithms: &ie.EUTRAintegrityProtectionAlgorithms{Value: allAlgorithms},
		},
		// 5. PDU Session Resource To Be Switched DL List
		PDUSessionResourceToBeSwitchedDLList: &ie.PDUSessionResourceToBeSwitchedDLList{
			List: []ie.PDUSessionResourceToBeSwitchedDLItem{
				{
					PDUSessionID:              &ie.PDUSessionID{Value: int64(pduSessionID)},
					PathSwitchRequestTransfer: &pathSwitchRequestTransfer,
				},
			},
		},
	}, nil
}

// buildPathSwitchRequestTransfer creates the PathSwitchRequestTransfer IE
// This contains the new RAN's GTP-U tunnel information for downlink
func (h *PathSwitchHandler) buildPathSwitchRequestTransfer(newRanN3IP string, newDLTEID uint32) (aper.OctetString, error) {
	// Build the transfer structure
	transfer := ie.PathSwitchRequestTransfer{
		// DL NG-U UP TNL Information (where UPF should send downlink packets)
		DLNGUUPTNLInformation: &ie.UPTransportLayerInformation{
			Choice: &ie.GTPTunnel{
				TransportLayerAddress: IPv4ToTransportLayerAddress(newRanN3IP),
				GTPTEID: &ie.GTPTEID{
					Value: aper.OctetString([]byte{
						byte(newDLTEID >> 24),
						byte(newDLTEID >> 16),
						byte(newDLTEID >> 8),
						byte(newDLTEID),
					}),
				},
			},
		},
		// QoS Flow Accepted List (typically QFI 1 for default bearer)
		QosFlowAcceptedList: &ie.QosFlowAcceptedList{
			List: []ie.QosFlowAcceptedItem{
				{
					QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 1},
				},
			},
		},
	}

	// Encode the transfer
	encoded, err := ie.MarshalBinary(&transfer)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PathSwitchRequestTransfer: %w", err)
	}

	return aper.OctetString(encoded), nil
}
